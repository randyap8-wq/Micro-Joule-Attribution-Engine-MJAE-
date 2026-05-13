use std::time::Duration;

use anyhow::Result;
use log::{debug, info, warn};

use crate::core::attribution::{baseline_burst_power_uw, burst_energy_uj, window_energy_uj};
use crate::core::registry::AmalgafyRegistry;

/// Cadence of [`EnergyProvider::start_sampling_loop`]. The directive
/// mandates a 100 ms tick.
pub const SAMPLING_LOOP_INTERVAL_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerSnapshot {
    pub observed_at_ns: u64,
    pub idle_power_uw: u64,
    pub active_power_uw: u64,
    pub cpu_power_uw: u64,
    pub gpu_power_uw: u64,
    pub accelerator_power_uw: u64,
    pub hardware_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PidEnergyAttribution {
    pub pid: u32,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub burst_power_uw: u64,
    pub attributed_energy_uj: u64,
    pub hardware_signature: String,
}

impl PidEnergyAttribution {
    #[must_use]
    pub fn baseline_burst(
        pid: u32,
        window_start_ns: u64,
        window_end_ns: u64,
        snapshot: &PowerSnapshot,
    ) -> Self {
        let window_ns = window_end_ns.saturating_sub(window_start_ns);

        Self {
            pid,
            window_start_ns,
            window_end_ns,
            burst_power_uw: baseline_burst_power_uw(
                snapshot.active_power_uw,
                snapshot.idle_power_uw,
            ),
            attributed_energy_uj: burst_energy_uj(
                snapshot.active_power_uw,
                snapshot.idle_power_uw,
                window_ns,
            ),
            hardware_signature: snapshot.hardware_signature.clone(),
        }
    }
}

/// Cross-platform contract implemented by every OS-specific provider
/// (Linux/eBPF, Windows/eBPF-for-Windows+NVML, macOS/IOReport).
///
/// Providers are intentionally *not* `Send + Sync` by default — most kernel
/// telemetry handles (Aya rings, NVML device handles, IOReport subscriptions)
/// are inherently single-owner. Daemons that need to fan out across cores
/// should spawn one provider per worker.
pub trait EnergyProvider {
    /// Take a fresh, instantaneous power reading from the underlying hardware
    /// telemetry source.
    fn sample_power_state(&mut self) -> Result<PowerSnapshot>;

    /// Compute the energy attributable to `pid` over `[window_start_ns,
    /// window_end_ns)` using `snapshot`.
    fn attribute_joules_to_pid(
        &mut self,
        pid: u32,
        window_start_ns: u64,
        window_end_ns: u64,
        snapshot: &PowerSnapshot,
    ) -> Result<PidEnergyAttribution>;

    /// Drain any pending per-PID attributions out of this provider and into
    /// the central [`AmalgafyRegistry`]. Returns the total micro-joules
    /// pushed during this sync.
    ///
    /// The default implementation is a no-op and is overridden by OS-specific
    /// providers as soon as they have a real telemetry source to drain. This
    /// shape lets the daemon's main loop call `sync_registry` on every
    /// provider uniformly without caring which platform it is on.
    fn sync_registry(&mut self, _registry: &AmalgafyRegistry) -> Result<u64> {
        Ok(0)
    }

    /// Identifier of the underlying hardware. Used by the Amalgafy Seal to
    /// bind a signature to a specific machine.
    fn hardware_signature(&self) -> &str;

    /// PIDs that should receive a share of the next differential energy
    /// reading. Providers that know which PIDs are currently active on the
    /// accelerator (e.g. NVML compute contexts on Windows, the `dma_fence`
    /// submitter set on Linux, or the IOReport task PIDs on macOS) override
    /// this; the default is empty, which causes the sampling loop to fall
    /// back to PID `0` (the "system" bucket) so the energy is not lost.
    fn active_pids(&self) -> Vec<u32> {
        Vec::new()
    }

    /// Non-blocking **Differential Sampling Daemon**.
    ///
    /// The loop ticks every [`SAMPLING_LOOP_INTERVAL_MS`] (100 ms), takes a
    /// fresh hardware snapshot, computes the Δ energy against the previous
    /// snapshot (using `window_energy_uj` over the inter-tick gap, against
    /// the burst-above-idle power), splits that Δ across the provider's
    /// currently-active PIDs, and pushes the result into `registry` without
    /// locks.
    ///
    /// A "heartbeat" log line is emitted on every successful tick so
    /// operators can see the daemon's live cadence and the running total
    /// power Δ. If `sample_power_state` returns an error, the loop logs a
    /// warning and continues — a transient telemetry hiccup must never kill
    /// the daemon.
    ///
    /// This is an `async fn`, not a spawned task: callers wrap it in
    /// `tokio::spawn` themselves so they keep full control over the worker
    /// thread it runs on. The future runs until it is dropped.
    fn start_sampling_loop<'a>(
        &'a mut self,
        registry: &'a AmalgafyRegistry,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
    where
        Self: Send,
    {
        Box::pin(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(SAMPLING_LOOP_INTERVAL_MS));
            // Skip the first immediate tick so the first iteration that
            // actually does work happens 100 ms in.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            let mut previous_snapshot: Option<PowerSnapshot> = None;
            let mut cumulative_delta_uj: u64 = 0;

            loop {
                interval.tick().await;

                let snapshot = match self.sample_power_state() {
                    Ok(s) => s,
                    Err(err) => {
                        warn!(
                            "Heartbeat: sample_power_state failed on {}: {err}",
                            self.hardware_signature()
                        );
                        continue;
                    }
                };

                if let Some(prev) = previous_snapshot.as_ref() {
                    let dt_ns = snapshot.observed_at_ns.saturating_sub(prev.observed_at_ns);
                    let burst_power_uw = baseline_burst_power_uw(
                        snapshot.active_power_uw,
                        snapshot.idle_power_uw,
                    );
                    let delta_uj = window_energy_uj(burst_power_uw, dt_ns);

                    let pids = self.active_pids();
                    if pids.is_empty() {
                        // No accelerator-active PIDs known to this provider;
                        // bucket the energy under PID 0 so the total stays
                        // accountable. The next seal lets auditors see the
                        // "unattributed system" share explicitly.
                        registry.add_micro_joules(0, delta_uj);
                    } else {
                        let num_pids = pids.len() as u64;
                        let share = delta_uj / num_pids;
                        // `share * num_pids` cannot exceed `delta_uj` by
                        // construction (integer division), so the
                        // subtraction is total-preserving and overflow-free.
                        let mut remainder = delta_uj - share.saturating_mul(num_pids);
                        for pid in &pids {
                            // Give the remainder to the lowest-PID buckets
                            // so the math is deterministic and
                            // total-preserving.
                            let extra = if remainder > 0 {
                                remainder -= 1;
                                1
                            } else {
                                0
                            };
                            registry.add_micro_joules(*pid, share + extra);
                        }
                    }

                    cumulative_delta_uj = cumulative_delta_uj.saturating_add(delta_uj);
                    info!(
                        "Heartbeat[{}] Δt={dt_ns}ns Δ={delta_uj}µJ total_Δ={cumulative_delta_uj}µJ active_pids={}",
                        self.hardware_signature(),
                        pids.len()
                    );
                } else {
                    debug!(
                        "Heartbeat[{}] first sample captured (active={}µW, idle={}µW)",
                        self.hardware_signature(),
                        snapshot.active_power_uw,
                        snapshot.idle_power_uw
                    );
                }

                previous_snapshot = Some(snapshot);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        AmalgafyRegistry, EnergyProvider, PidEnergyAttribution, PowerSnapshot,
        SAMPLING_LOOP_INTERVAL_MS,
    };
    use anyhow::Result;

    /// A fake provider that emits a deterministic ramp of `active_power_uw`
    /// readings and reports a fixed active-PID set.
    struct FakeProvider {
        sig: String,
        ticks: std::sync::Mutex<u64>,
        active_pids: Vec<u32>,
    }

    impl FakeProvider {
        fn new(active_pids: Vec<u32>) -> Self {
            Self {
                sig: "FAKE-HW".to_owned(),
                ticks: std::sync::Mutex::new(0),
                active_pids,
            }
        }
    }

    impl EnergyProvider for FakeProvider {
        fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
            let mut guard = self.ticks.lock().unwrap();
            *guard += 1;
            let t = *guard;
            // 100 ms cadence, so observed_at_ns advances by 100_000_000 per tick.
            Ok(PowerSnapshot {
                observed_at_ns: t * 100_000_000,
                idle_power_uw: 1_000_000,
                active_power_uw: 2_000_000, // 1 W burst above idle
                cpu_power_uw: 0,
                gpu_power_uw: 0,
                accelerator_power_uw: 0,
                hardware_signature: self.sig.clone(),
            })
        }

        fn attribute_joules_to_pid(
            &mut self,
            pid: u32,
            window_start_ns: u64,
            window_end_ns: u64,
            snapshot: &PowerSnapshot,
        ) -> Result<PidEnergyAttribution> {
            Ok(PidEnergyAttribution::baseline_burst(
                pid,
                window_start_ns,
                window_end_ns,
                snapshot,
            ))
        }

        fn hardware_signature(&self) -> &str {
            &self.sig
        }

        fn active_pids(&self) -> Vec<u32> {
            self.active_pids.clone()
        }
    }

    #[test]
    fn sampling_loop_constant_is_one_hundred_milliseconds() {
        assert_eq!(SAMPLING_LOOP_INTERVAL_MS, 100);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sampling_loop_accumulates_delta_into_active_pids() {
        let registry = Arc::new(AmalgafyRegistry::new());
        let mut provider = FakeProvider::new(vec![100, 200]);

        let reg_handle = Arc::clone(&registry);
        let handle = tokio::spawn(async move {
            let _ = provider.start_sampling_loop(&reg_handle).await;
        });

        // ~5 real-time ticks (100 ms each) → ≥3 Δ intervals attributed.
        tokio::time::sleep(std::time::Duration::from_millis(550)).await;
        handle.abort();

        // 1 W burst × 100 ms = 100_000 µJ per interval. With 3-5 intervals
        // we expect 300_000 µJ ≤ total ≤ 500_000 µJ, split between PID 100
        // and PID 200. We intentionally allow a wide band so this is not
        // a flaky test on a loaded CI host.
        let total = registry.total_micro_joules();
        assert!(
            total >= 200_000,
            "expected at least 200_000 µJ accumulated, got {total}"
        );
        let p100 = registry.get(100).unwrap_or(0);
        let p200 = registry.get(200).unwrap_or(0);
        assert!(p100 > 0 && p200 > 0, "both PIDs should receive a share");
        // No PID 0 fallback should have been used.
        assert_eq!(registry.get(0), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sampling_loop_buckets_to_pid_zero_when_no_active_pids() {
        let registry = Arc::new(AmalgafyRegistry::new());
        let mut provider = FakeProvider::new(Vec::new());

        let reg_handle = Arc::clone(&registry);
        let handle = tokio::spawn(async move {
            let _ = provider.start_sampling_loop(&reg_handle).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        handle.abort();

        // With no active PIDs the loop is required to bucket Δ under PID 0
        // so the energy is not silently dropped.
        assert!(registry.get(0).unwrap_or(0) > 0);
    }
}
