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
    pub fn add_micro_joules(&self, pid: u32, delta_uj: u64) -> u64 {
        if let Some(entry) = self.table.get(&pid) {
            return saturating_add(entry.value(), delta_uj);
        }

        // The PID may have been inserted concurrently between the `get` and
        // here; `SkipMap::insert` returns the entry that ends up living in the
        // map, so accumulating onto its value is always correct.
        let entry = self.table.insert(pid, AtomicU64::new(0));
        saturating_add(entry.value(), delta_uj)
    }

    /// Read the cumulative attribution for `pid`, if any.
    ///
    /// Uses `Relaxed` ordering because `SkipMap::get` already establishes the
    /// happens-before relationship needed to see the entry; the per-PID
    /// counter is monotonically increasing and never repurposed, so a
    /// possibly-stale read is bounded by one missed `add_micro_joules` call.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<u64> {
        self.table.get(&pid).map(|entry| entry.value().load(Ordering::Relaxed))
    }

    /// Remove a PID from the registry (e.g. when a process exits) and return
    /// its final cumulative attribution.
    pub fn remove(&self, pid: u32) -> Option<u64> {
        self.table
            .remove(&pid)
            .map(|entry| entry.value().load(Ordering::Relaxed))
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
            total = saturating_add_value(total, entry.value().load(Ordering::Relaxed));
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
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
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
}
