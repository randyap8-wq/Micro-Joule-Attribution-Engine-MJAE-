pub mod core;
pub mod providers;

pub use crate::core::{
    AMALGAFY_SEAL_INTERVAL_SECS, AmalgafyRegistry, AmalgafySeal, AmalgafySealPayload,
    AmalgafySigner, EnergyManifest, EnergyManifestPayload, EnergyProvider, HardwareIdentity,
    HardwareIdentitySource, PidEnergyAttribution, PowerSnapshot, SAMPLING_LOOP_INTERVAL_MS,
    baseline_burst_power_uw, burst_energy_uj, canonical_json, deterministic_attribution_uj,
    global_registry, nvml_window_energy_uj, rapl_fallback_uj, window_energy_uj,
};
#[cfg(target_os = "macos")]
pub use crate::providers::AppleSiliconProvider;
#[cfg(target_os = "linux")]
pub use crate::providers::{DmaFenceEvent, LinuxProvider};
#[cfg(target_os = "windows")]
pub use crate::providers::{NvmlComputeProcess, WindowsProvider};

