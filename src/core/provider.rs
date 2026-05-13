use anyhow::Result;

use crate::core::attribution::{baseline_burst_power_uw, burst_energy_uj};
use crate::core::registry::AmalgafyRegistry;

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
}

