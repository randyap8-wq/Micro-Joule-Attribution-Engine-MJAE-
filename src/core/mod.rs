mod attribution;
mod hardware;
mod manifest;
mod provider;
mod registry;
mod signer;

pub use attribution::{
    NANOSECONDS_PER_SECOND, baseline_burst_power_uw, burst_energy_uj, deterministic_attribution_uj,
    nvml_window_energy_uj, rapl_fallback_uj, window_energy_uj,
};
pub use hardware::{HardwareIdentity, HardwareIdentitySource};
#[allow(deprecated)]
pub use manifest::{EnergyManifest, EnergyManifestPayload};
pub use provider::{
    EnergyProvider, PidEnergyAttribution, PowerSnapshot, SAMPLING_LOOP_INTERVAL_MS,
};
pub use registry::{AmalgafyRegistry, global_registry};
pub use signer::{
    AMALGAFY_SEAL_INTERVAL_SECS, AmalgafySeal, AmalgafySealPayload, AmalgafySigner, canonical_json,
};
