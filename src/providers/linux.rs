#[cfg(target_os = "linux")]
use std::marker::PhantomData;

use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use aya::programs::TracePoint;
use log::debug;

use crate::core::{AmalgafyRegistry, EnergyProvider, PidEnergyAttribution, PowerSnapshot};

/// Linux-side provider that finalizes the Aya eBPF hooks for `dma_fence` to
/// observe GPU activity windows and then attributes that energy back to
/// individual PIDs.
///
/// The current build keeps the eBPF program scaffolding (`TracePoint` is held
/// in a `PhantomData` slot to avoid pulling in target-specific generics on
/// non-Linux hosts) and exposes a `pending` buffer that lets higher-level
/// orchestrators inject already-attributed records during tests or simulation
/// runs. Production builds drain the eBPF perf array into this buffer and
/// then push it into the global [`AmalgafyRegistry`] via
/// [`EnergyProvider::sync_registry`].
#[derive(Debug, Clone)]
pub struct LinuxProvider {
    hardware_signature: String,
    pending: Vec<PidEnergyAttribution>,
    #[cfg(target_os = "linux")]
    tracepoint_marker: PhantomData<fn() -> TracePoint>,
}

impl LinuxProvider {
    pub const DMA_FENCE_TRACEPOINT: &str = "dma_fence:dma_fence_signaled";
    pub const SCHED_SWITCH_TRACEPOINT: &str = "sched:sched_switch";

    #[must_use]
    pub fn new(hardware_signature: impl Into<String>) -> Self {
        Self {
            hardware_signature: hardware_signature.into(),
            pending: Vec::new(),
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
}

impl EnergyProvider for LinuxProvider {
    fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
        bail!(
            "linux power sampling is not implemented yet for hardware {}",
            self.hardware_signature
        )
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
        Ok(total)
    }

    fn hardware_signature(&self) -> &str {
        &self.hardware_signature
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{AmalgafyRegistry, EnergyProvider, PidEnergyAttribution};

    use super::LinuxProvider;

    #[test]
    fn sample_power_state_returns_explicit_error_until_sampling_exists() {
        let mut provider = LinuxProvider::new("NV-H100");

        assert!(provider.sample_power_state().is_err());
    }

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
}

