use anyhow::Result;

use crate::core::attribution::{baseline_burst_power_uw, burst_energy_uj};

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

pub trait EnergyProvider {
    fn sample_power_state(&mut self) -> Result<PowerSnapshot>;

    fn attribute_joules_to_pid(
        &mut self,
        pid: u32,
        window_start_ns: u64,
        window_end_ns: u64,
        snapshot: &PowerSnapshot,
    ) -> Result<PidEnergyAttribution>;
}
