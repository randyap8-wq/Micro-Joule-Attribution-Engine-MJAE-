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

#[cfg(test)]
mod tests {
    use super::{baseline_burst_power_uw, burst_energy_uj, window_energy_uj};

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
}
