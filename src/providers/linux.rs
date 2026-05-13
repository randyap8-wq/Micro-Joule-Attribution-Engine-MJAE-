#[cfg(target_os = "linux")]
use std::marker::PhantomData;

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use aya::programs::TracePoint;
use log::{debug, warn};

use crate::core::{
    AmalgafyRegistry, EnergyProvider, PidEnergyAttribution, PowerSnapshot, window_energy_uj,
};

/// A `dma_fence:dma_fence_signaled` event surfaced by the Aya eBPF hook.
///
/// The Linux GPU stack signals one `dma_fence` per logical work submission.
/// By bridging the *submitter* PID (recorded at `dma_fence_init` time) with
/// the *signaled* event, the daemon learns exactly which process consumed
/// the GPU between `t_submit` and `t_signal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaFenceEvent {
    /// Submitting process — the PID recorded when the fence was initialised.
    pub submitter_pid: u32,
    /// `t_submit`: when the fence was created (CLOCK_MONOTONIC ns).
    pub submitted_at_ns: u64,
    /// `t_signal`: when the fence was signalled (CLOCK_MONOTONIC ns).
    pub signaled_at_ns: u64,
    /// Average GPU power draw during the fence window, in microwatts.
    /// Sourced from sysfs hwmon or NVML and stamped onto the event by the
    /// daemon's correlator (the eBPF program itself only emits PIDs and
    /// timestamps; it does not read power).
    pub gpu_power_uw: u64,
}

/// Linux-side provider that bridges Aya eBPF `dma_fence` hooks with sysfs
/// power telemetry (RAPL for the package, hwmon for discrete GPUs) and feeds
/// attributed energy into the central [`AmalgafyRegistry`].
///
/// The provider keeps the eBPF program scaffolding (`TracePoint` is held in
/// a `PhantomData` slot to avoid pulling in target-specific generics on
/// non-Linux hosts) and exposes a `pending` buffer that lets higher-level
/// orchestrators inject already-attributed records during tests or
/// simulation runs.
#[derive(Debug, Clone)]
pub struct LinuxProvider {
    hardware_signature: String,
    pending: Vec<PidEnergyAttribution>,
    /// Submitter PIDs currently holding one or more in-flight `dma_fence`s
    /// mapped to the count of fences still outstanding for each PID.
    /// Surfaced to the differential sampling loop as the
    /// "accelerator-active" set so the 100 ms Δ energy is split across
    /// the right PIDs. We track a *count* (not just presence) so a
    /// completed fence doesn't prematurely mark a still-busy PID idle.
    active_pids: BTreeMap<u32, u32>,
    /// Most recent RAPL `energy_uj` reading, used to compute power between
    /// successive `sample_power_state` calls.
    rapl_state: Option<RaplState>,
    #[cfg(target_os = "linux")]
    tracepoint_marker: PhantomData<fn() -> TracePoint>,
}

#[derive(Debug, Clone, Copy)]
struct RaplState {
    energy_uj: u64,
    observed_at_ns: u64,
    /// Wrap point of the underlying counter, cached from
    /// `max_energy_range_uj` on the first successful read. RAPL counters
    /// reset to 0 when they exceed this value, so the delta between
    /// successive reads must be computed modulo `max_energy_range_uj + 1`.
    max_energy_uj: u64,
}

impl LinuxProvider {
    pub const DMA_FENCE_TRACEPOINT: &str = "dma_fence:dma_fence_signaled";
    pub const SCHED_SWITCH_TRACEPOINT: &str = "sched:sched_switch";
    /// Default RAPL energy counter path used by the provider when reading
    /// package energy from sysfs. This path is platform-dependent and may be
    /// unavailable on some systems (for example, AMD hosts, containers, or
    /// systems with restricted powercap access).
    pub const DEFAULT_RAPL_ENERGY_PATH: &str = "/sys/class/powercap/intel-rapl:0/energy_uj";
    /// Sibling sysfs file that reports the wrap point of
    /// [`Self::DEFAULT_RAPL_ENERGY_PATH`]. RAPL exposes a monotonically
    /// increasing µJ counter that resets to 0 when it exceeds this value,
    /// so a long-running daemon must subtract modulo `max_energy_range_uj`
    /// to avoid losing an entire wrap interval.
    pub const DEFAULT_RAPL_MAX_RANGE_PATH: &str =
        "/sys/class/powercap/intel-rapl:0/max_energy_range_uj";

    #[must_use]
    pub fn new(hardware_signature: impl Into<String>) -> Self {
        Self {
            hardware_signature: hardware_signature.into(),
            pending: Vec::new(),
            active_pids: BTreeMap::new(),
            rapl_state: None,
            #[cfg(target_os = "linux")]
            tracepoint_marker: PhantomData,
        }
    }

    /// Enqueue an already-attributed record for the next `sync_registry`.
    ///
    /// Production callers receive these records from the Aya `PerfEventArray`
    /// that is bound to the `dma_fence:dma_fence_signaled` tracepoint;
    /// integration tests construct them directly.
    pub fn enqueue_attribution(&mut self, attribution: PidEnergyAttribution) {
        self.pending.push(attribution);
    }

    /// Snapshot of pending records that have not yet been pushed into the
    /// registry. Exposed for diagnostics.
    #[must_use]
    pub fn pending(&self) -> &[PidEnergyAttribution] {
        &self.pending
    }

    /// Mark a PID as having submitted one more in-flight `dma_fence`.
    /// Called from the `dma_fence_init` eBPF callback to populate the
    /// active set the differential sampling loop reads from. Multiple
    /// concurrent fences from the same submitter are tracked as an
    /// in-flight *count*, not just presence, so a single signaled fence
    /// cannot prematurely mark a still-busy PID idle.
    pub fn mark_pid_active(&mut self, pid: u32) {
        let entry = self.active_pids.entry(pid).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Mark a PID as no longer holding any in-flight `dma_fence`. This is
    /// the "force-remove" path used when a process exits or the daemon
    /// otherwise knows the PID is gone; it clears the in-flight count
    /// regardless of value.
    pub fn mark_pid_idle(&mut self, pid: u32) {
        self.active_pids.remove(&pid);
    }

    /// Currently-active PIDs (submitters with one or more in-flight
    /// `dma_fence`s).
    #[must_use]
    pub fn active_pid_set(&self) -> Vec<u32> {
        self.active_pids.keys().copied().collect()
    }

    /// Correlate a `dma_fence_signaled` event with GPU power data and
    /// produce a [`PidEnergyAttribution`] that allocates the GPU energy
    /// burned during the fence window to the submitting PID.
    ///
    /// The Linux eBPF correlator path. The daemon's main loop calls this
    /// for every `DmaFenceEvent` drained out of the Aya perf array.
    ///
    /// Energy math: `E = P_gpu × (t_signal − t_submit)`, using the
    /// `window_energy_uj` helper so we keep u64-only arithmetic.
    ///
    /// On the in-flight set: we decrement the submitter's fence count by
    /// one (since this signaled fence is now complete). Only when the
    /// count reaches zero does the PID drop out of `active_pid_set` — a
    /// PID with other still-in-flight fences correctly stays "busy".
    pub fn correlate_fence(&mut self, event: DmaFenceEvent) -> PidEnergyAttribution {
        let window_ns = event.signaled_at_ns.saturating_sub(event.submitted_at_ns);
        let attributed_energy_uj = window_energy_uj(event.gpu_power_uw, window_ns);
        let attribution = PidEnergyAttribution {
            pid: event.submitter_pid,
            window_start_ns: event.submitted_at_ns,
            window_end_ns: event.signaled_at_ns,
            burst_power_uw: event.gpu_power_uw,
            attributed_energy_uj,
            hardware_signature: self.hardware_signature.clone(),
        };
        if let Some(count) = self.active_pids.get_mut(&event.submitter_pid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.active_pids.remove(&event.submitter_pid);
            }
        }
        self.pending.push(attribution.clone());
        attribution
    }

    /// Read the cumulative RAPL energy counter (in µJ) for the package and
    /// derive an instantaneous power reading by differencing against the
    /// previous read. The first call seeds the state and returns 0 power.
    ///
    /// RAPL counters wrap when they exceed `max_energy_range_uj`, so the
    /// delta is computed modulo that wrap point (`(curr − prev) mod
    /// (max + 1)`) — a plain `saturating_sub` would silently drop an
    /// entire wrap interval on long-running daemons.
    fn read_rapl_power_uw(&mut self) -> Result<(u64, u64)> {
        let raw = fs::read_to_string(Self::DEFAULT_RAPL_ENERGY_PATH)?;
        let energy_uj: u64 = raw.trim().parse()?;
        let observed_at_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0_u128),
        )
        .unwrap_or(0);

        // `max_energy_range_uj` is a small read that only changes when the
        // kernel module is reloaded; cache it after the first successful
        // read and fall back to u64::MAX (i.e. effectively non-wrapping)
        // if the sibling file is missing.
        let max_energy_uj = if let Some(prev) = self.rapl_state {
            prev.max_energy_uj
        } else {
            fs::read_to_string(Self::DEFAULT_RAPL_MAX_RANGE_PATH)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        };

        let power_uw = if let Some(prev) = self.rapl_state {
            // Modular delta: handle the RAPL counter wrapping back to 0
            // once it exceeds `max_energy_uj`.
            let delta_uj = if energy_uj >= prev.energy_uj {
                energy_uj - prev.energy_uj
            } else {
                // Counter wrapped: (max - prev) + curr + 1.
                let to_wrap = max_energy_uj.saturating_sub(prev.energy_uj);
                to_wrap.saturating_add(energy_uj).saturating_add(1)
            };
            let dt_ns = observed_at_ns.saturating_sub(prev.observed_at_ns);
            if dt_ns == 0 {
                0
            } else {
                // µJ over ns → µW: (delta_uj * 1e9) / dt_ns
                let p = u128::from(delta_uj) * 1_000_000_000_u128 / u128::from(dt_ns);
                u64::try_from(p).unwrap_or(u64::MAX)
            }
        } else {
            0
        };

        self.rapl_state = Some(RaplState {
            energy_uj,
            observed_at_ns,
            max_energy_uj,
        });
        Ok((power_uw, observed_at_ns))
    }
}

impl EnergyProvider for LinuxProvider {
    /// Sample the host's instantaneous power state by differencing the RAPL
    /// `energy_uj` counter. When `/sys/class/powercap/...` is unreadable
    /// (containers, hosts without RAPL, restricted permissions) the call
    /// errors instead of returning fabricated data — the sampling loop logs
    /// the error and skips the tick.
    fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
        let (power_uw, observed_at_ns) = match self.read_rapl_power_uw() {
            Ok(values) => values,
            Err(err) => bail!(
                "linux RAPL power sampling failed for hardware {}: {err}",
                self.hardware_signature
            ),
        };

        Ok(PowerSnapshot {
            observed_at_ns,
            // RAPL is a delta-energy counter, not an idle baseline. The
            // calibrator records the idle floor separately and the
            // attribution model subtracts it; for now we treat the lowest
            // observed RAPL power as the idle proxy via `idle_power_uw = 0`.
            idle_power_uw: 0,
            active_power_uw: power_uw,
            cpu_power_uw: power_uw,
            gpu_power_uw: 0,
            accelerator_power_uw: 0,
            hardware_signature: self.hardware_signature.clone(),
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

    fn sync_registry(&mut self, registry: &AmalgafyRegistry) -> Result<u64> {
        let mut total: u64 = 0;
        for attribution in self.pending.drain(..) {
            registry.add_micro_joules(attribution.pid, attribution.attributed_energy_uj);
            total = total.saturating_add(attribution.attributed_energy_uj);
        }
        debug!(
            "LinuxProvider::sync_registry pushed {total} µJ for hardware {}",
            self.hardware_signature
        );
        if total == 0 && !self.active_pids.is_empty() {
            // Visibility helper: an active set with no drained pending
            // attributions typically means the eBPF perf array hasn't been
            // flushed this cycle. Surface it so operators don't get silent
            // zeroes.
            warn!(
                "LinuxProvider::sync_registry: {} PIDs active but no fences signalled this cycle",
                self.active_pids.len()
            );
        }
        Ok(total)
    }

    fn hardware_signature(&self) -> &str {
        &self.hardware_signature
    }

    fn active_pids(&self) -> Vec<u32> {
        self.active_pid_set()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{AmalgafyRegistry, EnergyProvider, PidEnergyAttribution};

    use super::{DmaFenceEvent, LinuxProvider};

    #[test]
    fn sync_registry_drains_pending_attributions() {
        let mut provider = LinuxProvider::new("NV-H100");
        provider.enqueue_attribution(PidEnergyAttribution {
            pid: 100,
            window_start_ns: 0,
            window_end_ns: 1_000,
            burst_power_uw: 5_000_000,
            attributed_energy_uj: 5,
            hardware_signature: "NV-H100".to_owned(),
        });
        provider.enqueue_attribution(PidEnergyAttribution {
            pid: 100,
            window_start_ns: 1_000,
            window_end_ns: 2_000,
            burst_power_uw: 5_000_000,
            attributed_energy_uj: 7,
            hardware_signature: "NV-H100".to_owned(),
        });

        let registry = AmalgafyRegistry::new();
        let pushed = provider
            .sync_registry(&registry)
            .expect("sync_registry should succeed");

        assert_eq!(pushed, 12);
        assert_eq!(registry.get(100), Some(12));
        assert!(provider.pending().is_empty());
    }

    #[test]
    fn correlate_fence_attributes_gpu_window_to_submitter() {
        let mut provider = LinuxProvider::new("NV-H100");
        provider.mark_pid_active(4242);

        // 250 W GPU draw over 200 ms = 50 J = 50_000_000 µJ.
        let event = DmaFenceEvent {
            submitter_pid: 4242,
            submitted_at_ns: 1_000_000_000,
            signaled_at_ns: 1_200_000_000,
            gpu_power_uw: 250_000_000,
        };
        let attribution = provider.correlate_fence(event);

        assert_eq!(attribution.pid, 4242);
        assert_eq!(attribution.attributed_energy_uj, 50_000_000);
        assert_eq!(attribution.hardware_signature, "NV-H100");

        // After `_signaled`, the PID is no longer active.
        assert!(!provider.active_pid_set().contains(&4242));

        // And the attribution sits in the pending queue, ready to flow into
        // the registry on the next `sync_registry`.
        let registry = AmalgafyRegistry::new();
        provider.sync_registry(&registry).expect("drain should succeed");
        assert_eq!(registry.get(4242), Some(50_000_000));
    }

    #[test]
    fn active_pid_set_is_sorted_and_deduplicated() {
        let mut provider = LinuxProvider::new("NV-H100");
        provider.mark_pid_active(9);
        provider.mark_pid_active(1);
        provider.mark_pid_active(9);
        provider.mark_pid_active(4);

        assert_eq!(provider.active_pid_set(), vec![1, 4, 9]);
        assert_eq!(EnergyProvider::active_pids(&provider), vec![1, 4, 9]);

        provider.mark_pid_idle(4);
        assert_eq!(provider.active_pid_set(), vec![1, 9]);
    }
}
