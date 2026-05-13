#[cfg(target_os = "linux")]
use std::marker::PhantomData;

use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use aya::programs::TracePoint;

use crate::core::{EnergyProvider, PidEnergyAttribution, PowerSnapshot};

#[derive(Debug, Clone)]
pub struct LinuxProvider {
    hardware_signature: String,
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
            #[cfg(target_os = "linux")]
            tracepoint_marker: PhantomData,
        }
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
}

#[cfg(test)]
mod tests {
    use crate::core::EnergyProvider;

    use super::LinuxProvider;

    #[test]
    fn sample_power_state_returns_explicit_error_until_sampling_exists() {
        let mut provider = LinuxProvider::new("NV-H100");

        assert!(provider.sample_power_state().is_err());
    }
}
