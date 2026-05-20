//! The Amalgafy Registry: a lock-free, globally addressable mapping of
//! `PID -> cumulative attributed micro-joules`.
//!
//! The directive calls for "a lock-free, global `BTreeMap<u32, u64>`". `BTreeMap`
//! itself is not concurrent, so we back the registry with
//! [`crossbeam_skiplist::SkipMap`], which preserves the ordered semantics of a
//! `BTreeMap` while supporting wait-free reads and lock-free inserts. The
//! registry is the single source of truth that every OS-specific provider
//! pushes into through [`EnergyProvider::sync_registry`](crate::core::provider::EnergyProvider::sync_registry).
//!
//! The registry is intentionally append-only: providers contribute deltas via
//! [`AmalgafyRegistry::add_micro_joules`] and never have to take a mutex.
//! Background snapshotters can call [`AmalgafyRegistry::snapshot`] to obtain a
//! consistent, sorted view for sealing into an `EnergyManifest`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_skiplist::SkipMap;

/// Lock-free, ordered registry mapping `PID -> cumulative micro-joules`.
///
/// This type is `Send + Sync` and supports concurrent updates from any number
/// of providers without locking. Internally it is a `SkipMap<u32, AtomicU64>`,
/// which keeps the ordered semantics expected of a `BTreeMap<u32, u64>` while
/// removing every blocking primitive from the hot path.
#[derive(Debug, Default)]
pub struct AmalgafyRegistry {
    table: SkipMap<u32, AtomicU64>,
}

impl AmalgafyRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: SkipMap::new(),
        }
    }

    /// Atomically accumulate `delta_uj` micro-joules into the slot for `pid`.
    ///
    /// Returns the new cumulative total for the PID. Saturates at `u64::MAX`
    /// so long-running daemons never overflow silently.
    ///
    /// # Concurrency
    ///
    /// First-insert correctness is non-trivial here: a naive
    /// `if get().is_none() { insert(zero) }` pattern has a TOCTOU race
    /// because `SkipMap::insert` *replaces* on collision rather than
    /// returning the entry that ends up living in the map. Two providers
    /// (e.g. Linux RAPL + a GPU provider) racing on the same
    /// never-before-seen PID would each insert a fresh zero slot, the
    /// second insert silently evicting the first, and the delta the first
    /// thread accumulated onto its (now-orphaned) entry would be lost.
    /// Worse, [`SkipMap::get`] called right after an `insert` can briefly
    /// observe `None` in the window where a concurrent insert has marked
    /// the previous node's tower for removal but has not yet spliced in
    /// its replacement node, so even a re-fetch is not race-free.
    ///
    /// We sidestep the whole class of races by using
    /// [`SkipMap::get_or_insert`], which is documented as inserting the
    /// supplied value *only if the key is absent* and otherwise returning
    /// the existing entry. Every concurrent caller sees the same canonical
    /// `AtomicU64` slot, so every delta is accumulated and none is dropped.
    pub fn add_micro_joules(&self, pid: u32, delta_uj: u64) -> u64 {
        // Fast path — PID already tracked. Avoids the AtomicU64 allocation
        // (and the epoch pin) on the hot path; `get_or_insert` would do the
        // same job correctness-wise but always pays the allocation.
        if let Some(entry) = self.table.get(&pid) {
            return saturating_add(entry.value(), delta_uj);
        }

        // Cold path — `get_or_insert` returns the entry that ends up living
        // in the map. If two threads race here, exactly one
        // freshly-allocated `AtomicU64` wins and every racer accumulates
        // onto it.
        let entry = self.table.get_or_insert(pid, AtomicU64::new(0));
        saturating_add(entry.value(), delta_uj)
    }

    /// Read the cumulative attribution for `pid`, if any.
    ///
    /// Uses `Acquire` ordering so the load synchronises with the `AcqRel`
    /// release store performed by [`add_micro_joules`]; the per-PID counter
    /// is monotonically increasing and never repurposed, but a relaxed
    /// load could observe a stale value indefinitely on weakly-ordered
    /// architectures, which `Acquire` rules out at zero cost on x86_64 /
    /// AArch64.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<u64> {
        self.table
            .get(&pid)
            .map(|entry| entry.value().load(Ordering::Acquire))
    }

    /// Remove a PID from the registry (e.g. when a process exits) and return
    /// its final cumulative attribution.
    pub fn remove(&self, pid: u32) -> Option<u64> {
        self.table
            .remove(&pid)
            .map(|entry| entry.value().load(Ordering::Acquire))
    }

    /// Number of PIDs currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// `true` when no PID has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Sum every tracked PID's micro-joule total.
    ///
    /// The walk is wait-free and may observe interleaved writes; that is
    /// acceptable because the resulting total is a strict lower bound on the
    /// real cumulative energy spent so far.
    #[must_use]
    pub fn total_micro_joules(&self) -> u64 {
        let mut total: u64 = 0;
        for entry in self.table.iter() {
            total = saturating_add_value(total, entry.value().load(Ordering::Acquire));
        }
        total
    }

    /// Take an ordered snapshot of `(pid, cumulative_uj)` tuples.
    ///
    /// Because the underlying map is ordered, the returned `Vec` is sorted by
    /// PID, which makes downstream canonical-JSON encoding deterministic.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(u32, u64)> {
        self.table
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Acquire)))
            .collect()
    }
}

#[inline]
fn saturating_add(cell: &AtomicU64, delta: u64) -> u64 {
    // Saturating compare-and-swap loop. Avoids overflow without a Mutex.
    let mut current = cell.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(delta);
        match cell.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

#[inline]
fn saturating_add_value(lhs: u64, rhs: u64) -> u64 {
    lhs.saturating_add(rhs)
}

/// Process-wide handle to the Amalgafy Registry.
///
/// The daemon is expected to call [`global_registry`] once at startup and
/// share the returned reference across providers. Using a `OnceLock` keeps the
/// initialization lock-free after the first call.
static GLOBAL_REGISTRY: OnceLock<AmalgafyRegistry> = OnceLock::new();

/// Obtain the process-wide [`AmalgafyRegistry`], constructing it on first use.
#[must_use]
pub fn global_registry() -> &'static AmalgafyRegistry {
    GLOBAL_REGISTRY.get_or_init(AmalgafyRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::{AmalgafyRegistry, global_registry};

    #[test]
    fn registry_accumulates_per_pid_deltas() {
        let registry = AmalgafyRegistry::new();

        assert_eq!(registry.add_micro_joules(1024, 250), 250);
        assert_eq!(registry.add_micro_joules(1024, 750), 1_000);
        assert_eq!(registry.add_micro_joules(2048, 42), 42);

        assert_eq!(registry.get(1024), Some(1_000));
        assert_eq!(registry.get(2048), Some(42));
        assert_eq!(registry.total_micro_joules(), 1_042);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn registry_snapshot_is_sorted_by_pid() {
        let registry = AmalgafyRegistry::new();
        registry.add_micro_joules(9, 10);
        registry.add_micro_joules(1, 30);
        registry.add_micro_joules(4, 20);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot, vec![(1, 30), (4, 20), (9, 10)]);
    }

    #[test]
    fn registry_remove_returns_final_total() {
        let registry = AmalgafyRegistry::new();
        registry.add_micro_joules(7, 500);
        registry.add_micro_joules(7, 500);

        assert_eq!(registry.remove(7), Some(1_000));
        assert_eq!(registry.get(7), None);
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_saturates_instead_of_wrapping() {
        let registry = AmalgafyRegistry::new();
        registry.add_micro_joules(1, u64::MAX - 5);
        let total = registry.add_micro_joules(1, 1_000);

        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn global_registry_returns_the_same_handle_every_time() {
        let first = global_registry() as *const _;
        let second = global_registry() as *const _;

        assert_eq!(first, second);
    }

    #[test]
    fn concurrent_first_insert_does_not_lose_deltas() {
        // Regression test for the TOCTOU window between `get` and `insert`
        // in `add_micro_joules`. With the buggy implementation, two threads
        // racing on a never-before-seen PID would each `insert` a fresh
        // zero slot — the second insert silently overwriting the first —
        // and the delta the first thread accumulated onto its
        // now-orphaned entry would be lost. After the fix both threads
        // accumulate onto the same `get_or_insert`-returned canonical slot,
        // and no delta can be dropped.
        //
        // The per-PID and total assertions are what actually catch the
        // regression: each thread's local `add_micro_joules` return value
        // would still be >= 1 under the buggy path (it always at least
        // adds 1 onto the AtomicU64 it just installed before that
        // AtomicU64 is later overwritten by a racer), so only the
        // post-hoc registry totals can prove no delta was lost.
        use std::sync::Arc;
        use std::thread;

        const THREADS: usize = 16;
        const ITERATIONS: usize = 200;

        let registry = Arc::new(AmalgafyRegistry::new());
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));

        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                for i in 0..ITERATIONS {
                    // Use a fresh, never-before-seen PID per iteration so
                    // every increment hits the cold-path race window.
                    let pid = (i as u32) * 1_000 + 1;
                    barrier.wait();
                    registry.add_micro_joules(pid, 1);
                }
            }));
        }
        for h in handles {
            h.join().expect("worker should not panic");
        }

        // The per-PID totals must sum exactly to THREADS*ITERATIONS: no
        // delta may be dropped during the cold-path race.
        assert_eq!(registry.total_micro_joules(), (THREADS * ITERATIONS) as u64);
        for i in 0..ITERATIONS {
            let pid = (i as u32) * 1_000 + 1;
            assert_eq!(registry.get(pid), Some(THREADS as u64));
        }
    }
}
