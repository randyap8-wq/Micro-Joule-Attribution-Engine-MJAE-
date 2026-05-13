pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

#[inline]
pub fn baseline_burst_power_uw(active_power_uw: u64, idle_power_uw: u64) -> u64 {
    active_power_uw.saturating_sub(idle_power_uw)
}

#[inline]
pub fn window_energy_uj(power_uw: u64, window_ns: u64) -> u64 {
    let whole_seconds = window_ns / NANOSECONDS_PER_SECOND;
    let remainder_ns = window_ns % NANOSECONDS_PER_SECOND;

    power_uw
        .saturating_mul(whole_seconds)
        .saturating_add(power_uw.saturating_mul(remainder_ns) / NANOSECONDS_PER_SECOND)
}

#[inline]
pub fn burst_energy_uj(active_power_uw: u64, idle_power_uw: u64, window_ns: u64) -> u64 {
    window_energy_uj(
        baseline_burst_power_uw(active_power_uw, idle_power_uw),
        window_ns,
    )
}

/// Deterministic Attribution Model:
///
/// `E_attributed = (P_total − P_idle) × (T_process_on_accelerator / T_total_busy) × T_total_busy`
///
/// Algebraically this simplifies to
/// `E_attributed = (P_total − P_idle) × T_process_on_accelerator`, but we keep
/// the ratio explicit because callers that lack per-process accelerator timing
/// fall back to the bare burst-energy model. The function returns micro-joules.
///
/// * `total_power_uw` — the instantaneous package power including idle.
/// * `idle_power_uw` — the calibrated idle baseline for the same package.
/// * `process_on_accelerator_ns` — time the target PID held the accelerator
///   (e.g. a GPU `dma_fence` window on Linux, an NVML compute context on
///   Windows, or an IOReport "GPU energy" window on macOS).
/// * `total_busy_ns` — the union of all PIDs' accelerator-busy time over the
///   sampling window. Must be `>= process_on_accelerator_ns`.
#[inline]
#[must_use]
pub fn deterministic_attribution_uj(
    total_power_uw: u64,
    idle_power_uw: u64,
    process_on_accelerator_ns: u64,
    total_busy_ns: u64,
) -> u64 {
    if total_busy_ns == 0 {
        return 0;
    }

    let burst_power_uw = total_power_uw.saturating_sub(idle_power_uw);
    let proc_ns = process_on_accelerator_ns.min(total_busy_ns);

    // (burst_power_uw * proc_ns) is the energy the PID burned during its
    // accelerator-busy slice. Convert nanoseconds-of-microwatts into
    // micro-joules by dividing by 1e9, using u128 to avoid intermediate
    // overflow on long-running daemons.
    let numerator: u128 = u128::from(burst_power_uw) * u128::from(proc_ns);
    let micro_joules = numerator / u128::from(NANOSECONDS_PER_SECOND);
    u64::try_from(micro_joules).unwrap_or(u64::MAX)
}

/// CPU-only fallback used when no accelerator activity is detected.
///
/// `rapl_uj_delta` is the difference between two consecutive reads of the
/// Linux RAPL `energy_uj` MSR (or its Windows / macOS equivalent). Because
/// RAPL already integrates power over time, no time component is required.
///
/// When [`deterministic_attribution_uj`] would return zero (because the
/// accelerator was idle), the runtime should multiply this value by the
/// process's CPU-time share of the sampling window.
#[inline]
#[must_use]
pub fn rapl_fallback_uj(rapl_uj_delta: u64, cpu_share_micros: u32) -> u64 {
    // `cpu_share_micros` is the per-million share the process spent on the
    // CPU during the window (i.e. cpu_time_ns / wall_ns * 1_000_000). Using a
    // u32 keeps the math branch-free.
    let share = u64::from(cpu_share_micros.min(1_000_000));
    let scaled: u128 = u128::from(rapl_uj_delta) * u128::from(share);
    u64::try_from(scaled / 1_000_000).unwrap_or(u64::MAX)
}

/// Convert an NVML power reading in **milliwatts** measured over a window of
/// `dt_ms` **milliseconds** into **micro-joules**.
///
/// `P(mW) × Δt(ms) = E(µJ)`. This is the closed-form energy used by the
/// Windows / NVML sampling loop, where `nvmlDeviceGetPowerUsage` returns
/// milliwatts and the daemon's `tokio::time::interval` gives Δt in
/// milliseconds.
#[inline]
#[must_use]
pub fn nvml_window_energy_uj(power_mw: u64, dt_ms: u64) -> u64 {
    let energy: u128 = u128::from(power_mw) * u128::from(dt_ms);
    u64::try_from(energy).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        baseline_burst_power_uw, burst_energy_uj, deterministic_attribution_uj,
        nvml_window_energy_uj, rapl_fallback_uj, window_energy_uj,
    };

    #[test]
    fn burst_model_subtracts_idle_power() {
        assert_eq!(baseline_burst_power_uw(8_500_000, 3_000_000), 5_500_000);
        assert_eq!(
            burst_energy_uj(8_500_000, 3_000_000, 2_000_000_000),
            11_000_000
        );
    }

    #[test]
    fn burst_model_saturates_when_system_is_idle() {
        assert_eq!(baseline_burst_power_uw(900_000, 1_100_000), 0);
        assert_eq!(burst_energy_uj(900_000, 1_100_000, 10_000_000), 0);
    }

    #[test]
    fn window_energy_handles_subsecond_windows_with_u64_only_math() {
        assert_eq!(window_energy_uj(5_000_000, 250_000_000), 1_250_000);
    }

    #[test]
    fn deterministic_attribution_splits_burst_energy_by_accelerator_time() {
        // 8.5W - 3.0W = 5.5W burst. PID held the GPU for half of the busy
        // window, so it gets half of the burst energy.
        let attributed = deterministic_attribution_uj(
            8_500_000,
            3_000_000,
            1_000_000_000,
            2_000_000_000,
        );
        assert_eq!(attributed, 5_500_000);
    }

    #[test]
    fn deterministic_attribution_returns_zero_when_accelerator_is_idle() {
        assert_eq!(deterministic_attribution_uj(8_500_000, 3_000_000, 0, 0), 0);
    }

    #[test]
    fn rapl_fallback_scales_by_cpu_share() {
        // 10 mJ delta, process owned 25% of the CPU.
        assert_eq!(rapl_fallback_uj(10_000, 250_000), 2_500);
    }

    #[test]
    fn rapl_fallback_clamps_share_to_one_hundred_percent() {
        assert_eq!(rapl_fallback_uj(10_000, 5_000_000), 10_000);
    }

    #[test]
    fn nvml_window_energy_uses_milliwatt_millisecond_product() {
        // 150 W = 150_000 mW. Over 100 ms that's 15 J = 15_000_000 µJ.
        assert_eq!(nvml_window_energy_uj(150_000, 100), 15_000_000);
    }

    #[test]
    fn nvml_window_energy_saturates_instead_of_overflowing() {
        assert_eq!(nvml_window_energy_uj(u64::MAX, u64::MAX), u64::MAX);
    }
}

