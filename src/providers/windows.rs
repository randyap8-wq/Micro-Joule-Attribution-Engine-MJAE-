#![cfg(target_os = "windows")]

//! Windows-side provider.
//!
//! Windows lacks a direct equivalent to Linux's `dma_fence` tracepoint, so we
//! lean on two sources of telemetry that *are* first-class on modern Windows
//! Server installs:
//!
//! * **eBPF-for-Windows** — used at a higher layer to capture process
//!   lifecycle events and the moment a process opens a handle to Direct3D /
//!   CUDA. By 2026 the verifier supports the `process_load` and
//!   `image_load_notify` hooks we need, and we represent the resulting
//!   per-PID busy windows as [`crate::core::PidEnergyAttribution`] entries
//!   that flow through [`WindowsProvider::enqueue_attribution`].
//! * **NVML** (`nvml.dll`) — Nvidia's Management Library exposes both the
//!   list of *Compute Contexts* (PID + memory + SM occupancy) and a live
//!   `nvmlDeviceGetPowerUsage` reading in milliwatts. We talk to NVML through
//!   raw FFI so the binary stays small and we don't drag in a heavy wrapper
//!   crate.
//!
//! The provider keeps allocations on the hot path low: the internal
//! `Vec<NvmlProcessInfoV3>` scratch buffer used to talk to NVML is reused
//! across samples (its capacity only grows), and PIDs are pushed into the
//! [`AmalgafyRegistry`] without any intermediate `Vec<u8>` serialization.
//! Public accessors return owned `Vec`s so callers can hold them past the
//! next sample without lifetime gymnastics.

use std::ffi::{CStr, c_uint, c_ulonglong};
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::Once;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use log::{debug, warn};

use crate::core::{
    AmalgafyRegistry, EnergyProvider, HardwareIdentitySource, PidEnergyAttribution, PowerSnapshot,
    deterministic_attribution_uj, nvml_window_energy_uj,
};

// ---------------------------------------------------------------------------
// NVML FFI
//
// We declare only the entry points we need. NVML guarantees ABI stability for
// the `*_v2` / `*_v3` suffixed symbols, which is what we link to.
// ---------------------------------------------------------------------------

const NVML_SUCCESS: c_int = 0;
const NVML_ERROR_INSUFFICIENT_SIZE: c_int = 7;
const NVML_DEVICE_UUID_BUFFER_SIZE: usize = 80;
const NVML_DEVICE_SERIAL_BUFFER_SIZE: usize = 30;

type NvmlDeviceT = *mut c_void;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct NvmlProcessInfoV3 {
    pid: c_uint,
    used_gpu_memory: c_ulonglong,
    gpu_instance_id: c_uint,
    compute_instance_id: c_uint,
}

#[link(name = "nvml")]
unsafe extern "C" {
    fn nvmlInit_v2() -> c_int;
    // `nvmlShutdown` is intentionally retained but unused: per
    // `WindowsProvider::drop` the daemon's main() is responsible for the
    // process-wide NVML shutdown. The symbol stays declared so a future
    // integration point doesn't have to re-add the FFI declaration.
    #[allow(dead_code)]
    fn nvmlShutdown() -> c_int;
    fn nvmlDeviceGetCount_v2(count: *mut c_uint) -> c_int;
    fn nvmlDeviceGetHandleByIndex_v2(index: c_uint, device: *mut NvmlDeviceT) -> c_int;
    fn nvmlDeviceGetSerial(device: NvmlDeviceT, serial: *mut c_char, length: c_uint) -> c_int;
    fn nvmlDeviceGetUUID(device: NvmlDeviceT, uuid: *mut c_char, length: c_uint) -> c_int;
    fn nvmlDeviceGetPowerUsage(device: NvmlDeviceT, power_mw: *mut c_uint) -> c_int;
    fn nvmlDeviceGetComputeRunningProcesses_v3(
        device: NvmlDeviceT,
        info_count: *mut c_uint,
        infos: *mut NvmlProcessInfoV3,
    ) -> c_int;
    fn nvmlErrorString(result: c_int) -> *const c_char;
}

static NVML_INIT: Once = Once::new();
static NVML_INIT_RESULT: AtomicI32 = AtomicI32::new(NVML_SUCCESS);

fn ensure_nvml_initialized() -> Result<()> {
    NVML_INIT.call_once(|| {
        // SAFETY: nvmlInit_v2 is documented as safe to call multiple times in
        // the same process but we still gate it behind a Once.
        let code = unsafe { nvmlInit_v2() };
        NVML_INIT_RESULT.store(code, Ordering::SeqCst);
    });
    let result = NVML_INIT_RESULT.load(Ordering::SeqCst);
    if result != NVML_SUCCESS {
        bail!("nvmlInit_v2 failed: {}", nvml_error_string(result));
    }
    Ok(())
}

fn nvml_error_string(code: c_int) -> String {
    // SAFETY: nvmlErrorString returns a static, NUL-terminated C string.
    let ptr = unsafe { nvmlErrorString(code) };
    if ptr.is_null() {
        return format!("nvml error {code}");
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn check_nvml(code: c_int, context: &str) -> Result<()> {
    if code == NVML_SUCCESS {
        Ok(())
    } else {
        Err(anyhow!("{context}: {}", nvml_error_string(code)))
    }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// One row returned by NVML when we ask "which PIDs currently hold a CUDA
/// compute context on this GPU".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmlComputeProcess {
    pub pid: u32,
    pub used_gpu_memory_bytes: u64,
    pub gpu_instance_id: u32,
    pub compute_instance_id: u32,
}

/// Tracks the previous busy snapshot for a GPU so we can compute deltas
/// between consecutive `sample_power_state` calls.
#[derive(Debug, Clone, Default)]
struct GpuBusyState {
    last_sample_ns: u64,
    last_pids: Vec<u32>,
}

#[derive(Debug)]
pub struct WindowsProvider {
    hardware_signature: String,
    /// Records which NVML probe actually produced [`Self::hardware_signature`].
    /// Surfaced to the cross-platform [`HardwareIdentity`](crate::core::HardwareIdentity)
    /// probe so seals can distinguish a serial-derived fingerprint from a
    /// UUID-derived (or synthetic) fallback.
    signature_source: HardwareIdentitySource,
    /// Index of the NVIDIA device this provider is bound to. Multi-GPU
    /// daemons spin up one provider per device.
    device_index: u32,
    device_handle: NvmlDeviceT,
    /// Last known busy state, used to compute `T_total_busy` deltas.
    busy_state: GpuBusyState,
    /// Compute-process scratch buffer reused across samples (zero-copy).
    compute_scratch: Vec<NvmlProcessInfoV3>,
    /// Pending attributions waiting to be drained into the registry. eBPF
    /// callbacks and direct callers both push through here.
    pending: Vec<PidEnergyAttribution>,
}

// SAFETY: NVML device handles are thread-safe per the NVML documentation —
// the library uses internal locking. We still keep one provider per device
// per worker by convention, but cross-thread `Send` is sound.
unsafe impl Send for WindowsProvider {}

impl WindowsProvider {
    /// Construct a provider bound to NVML device `device_index`.
    ///
    /// The hardware signature is auto-derived from NVML's serial number; this
    /// is exactly the value that gets sealed into the Amalgafy Manifest.
    pub fn new(device_index: u32) -> Result<Self> {
        ensure_nvml_initialized()?;

        // SAFETY: we just initialized NVML successfully.
        let mut handle: NvmlDeviceT = std::ptr::null_mut();
        let code = unsafe { nvmlDeviceGetHandleByIndex_v2(device_index, &mut handle) };
        check_nvml(code, "nvmlDeviceGetHandleByIndex_v2")?;

        let (serial, signature_source) = match read_nvml_serial(handle) {
            Ok(s) => (s, HardwareIdentitySource::WindowsNvmlSerial),
            Err(err) => {
                warn!("nvmlDeviceGetSerial failed, falling back to UUID: {err}");
                match read_nvml_uuid(handle) {
                    Ok(uuid) => (uuid, HardwareIdentitySource::WindowsNvmlUuid),
                    Err(_) => (
                        format!("nvml-device-{device_index}"),
                        HardwareIdentitySource::Synthetic,
                    ),
                }
            }
        };

        Ok(Self {
            hardware_signature: serial,
            signature_source,
            device_index,
            device_handle: handle,
            busy_state: GpuBusyState::default(),
            compute_scratch: Vec::with_capacity(32),
            pending: Vec::new(),
        })
    }

    /// Discover how many NVIDIA devices are visible. Useful for daemons that
    /// want to spawn one provider per device.
    pub fn device_count() -> Result<u32> {
        ensure_nvml_initialized()?;
        let mut count: c_uint = 0;
        // SAFETY: nvmlInit_v2 succeeded; we own the `count` slot.
        let code = unsafe { nvmlDeviceGetCount_v2(&mut count) };
        check_nvml(code, "nvmlDeviceGetCount_v2")?;
        Ok(count)
    }

    /// Borrow the NVML-derived hardware signature as an owned `String`.
    /// Used by the cross-platform [`crate::core::HardwareIdentity`] probe to
    /// surface this device's UUID without losing exclusive ownership of the
    /// `WindowsProvider`.
    #[must_use]
    pub fn hardware_signature_string(&self) -> String {
        self.hardware_signature.clone()
    }

    /// Identifier of which NVML probe (serial, UUID, synthetic) actually
    /// produced [`Self::hardware_signature_string`]. Surfaced so the
    /// cross-platform hardware-identity probe can label the source on the
    /// sealed payload.
    #[must_use]
    pub fn signature_source(&self) -> HardwareIdentitySource {
        self.signature_source
    }

    /// Read the GPU's instantaneous power draw in **milliwatts** —
    /// `nvmlDeviceGetPowerUsage`'s native unit. Combined with
    /// [`crate::core::nvml_window_energy_uj`] this gives µJ over a Δt
    /// window without any unit-conversion hand-rolling at the call site.
    pub fn read_power_mw(&self) -> Result<u32> {
        let mut milliwatts: c_uint = 0;
        // SAFETY: device handle was vended by nvmlDeviceGetHandleByIndex_v2.
        let code = unsafe { nvmlDeviceGetPowerUsage(self.device_handle, &mut milliwatts) };
        check_nvml(code, "nvmlDeviceGetPowerUsage")?;
        Ok(milliwatts)
    }

    /// Return the list of NVIDIA *compute contexts* currently running on this
    /// device. Each call queries NVML and copies the result into a fresh
    /// `Vec`; the internal NVML scratch buffer is reused, but the returned
    /// `Vec` is owned by the caller and is safe to hold across subsequent
    /// samples.
    pub fn list_compute_processes(&mut self) -> Result<Vec<NvmlComputeProcess>> {
        let raw = self.sample_compute_processes()?;
        Ok(raw
            .iter()
            .map(|p| NvmlComputeProcess {
                pid: p.pid,
                used_gpu_memory_bytes: p.used_gpu_memory,
                gpu_instance_id: p.gpu_instance_id,
                compute_instance_id: p.compute_instance_id,
            })
            .collect())
    }

    /// Manually enqueue an attribution. Used by the eBPF-for-Windows callback
    /// path that observes Direct3D / CUDA handle opens.
    pub fn enqueue_attribution(&mut self, attribution: PidEnergyAttribution) {
        self.pending.push(attribution);
    }

    /// Read the GPU's instantaneous power draw in microwatts.
    pub fn read_power_uw(&self) -> Result<u64> {
        Ok(u64::from(self.read_power_mw()?) * 1_000)
    }

    /// Attribute energy to each currently-running compute PID over a
    /// `dt_ms` window using the NVML power×time formula
    /// `P(mW) × Δt(ms) = E(µJ)`, push the per-PID totals into `registry`,
    /// and return the freshly allocated per-PID list so callers can hand it
    /// to the [`crate::core::AmalgafySigner`] for sealing.
    ///
    /// This is the "Windows Differential Sampling" path. Daemons that prefer
    /// the deterministic-attribution model can use [`attribute_window`]
    /// instead.
    pub fn sample_window_energy(
        &mut self,
        window_start_ns: u64,
        window_end_ns: u64,
        dt_ms: u64,
        registry: &AmalgafyRegistry,
    ) -> Result<Vec<PidEnergyAttribution>> {
        let power_mw = self.read_power_mw()?;
        let processes = self.sample_compute_processes()?.to_vec();

        let total_window_uj = nvml_window_energy_uj(u64::from(power_mw), dt_ms);
        if processes.is_empty() || total_window_uj == 0 {
            return Ok(Vec::new());
        }

        let num_processes = processes.len() as u64;
        let share = total_window_uj / num_processes;
        let mut remainder = total_window_uj - share * num_processes;

        let mut result = Vec::with_capacity(processes.len());
        let burst_power_uw = u64::from(power_mw) * 1_000;
        for proc in processes {
            let extra = if remainder > 0 {
                remainder -= 1;
                1
            } else {
                0
            };
            let attributed = share + extra;
            registry.add_micro_joules(proc.pid, attributed);
            result.push(PidEnergyAttribution {
                pid: proc.pid,
                window_start_ns,
                window_end_ns,
                burst_power_uw,
                attributed_energy_uj: attributed,
                hardware_signature: self.hardware_signature.clone(),
            });
        }

        self.busy_state.last_sample_ns = window_end_ns;
        self.busy_state.last_pids = result.iter().map(|r| r.pid).collect();

        Ok(result)
    }

    /// Attribute energy to each currently-running compute PID using the
    /// deterministic model, push the per-PID totals into `registry`, and
    /// return the freshly allocated per-PID list so callers can hand it to
    /// the [`crate::core::AmalgafySigner`] for sealing.
    ///
    /// `idle_power_uw` is the calibrated idle baseline for this GPU (queried
    /// once at startup and persisted in the daemon's config). The returned
    /// `Vec` is owned by the caller; the provider keeps no reference to it.
    pub fn attribute_window(
        &mut self,
        window_start_ns: u64,
        window_end_ns: u64,
        idle_power_uw: u64,
        registry: &AmalgafyRegistry,
    ) -> Result<Vec<PidEnergyAttribution>> {
        let total_power_uw = self.read_power_uw()?;
        let processes = self.sample_compute_processes()?.to_vec();

        if processes.is_empty() {
            debug!(
                "WindowsProvider[{}] observed an idle GPU; daemon should fall back to RAPL",
                self.device_index
            );
            return Ok(Vec::new());
        }

        let window_ns = window_end_ns.saturating_sub(window_start_ns);
        // Without dma_fence-grade per-PID accelerator timing on Windows, we
        // fairly split the busy window across every active compute context.
        // This gives each PID `(P_total - P_idle) × window_ns / N`, which is
        // exactly what the deterministic attribution model produces when
        // `T_process_on_accelerator = window_ns / N` and `T_total_busy =
        // window_ns`. A finer-grained eBPF-for-Windows hook (e.g. on the
        // CUDA / Direct3D command-submission ioctl) can replace this with
        // per-PID measured times by calling `enqueue_attribution` directly.
        let num_processes = processes.len() as u64;
        let per_process_ns = window_ns / num_processes;

        let mut result = Vec::with_capacity(processes.len());
        for proc in processes {
            let attributed = deterministic_attribution_uj(
                total_power_uw,
                idle_power_uw,
                per_process_ns,
                window_ns,
            );
            registry.add_micro_joules(proc.pid, attributed);
            result.push(PidEnergyAttribution {
                pid: proc.pid,
                window_start_ns,
                window_end_ns,
                burst_power_uw: total_power_uw.saturating_sub(idle_power_uw),
                attributed_energy_uj: attributed,
                hardware_signature: self.hardware_signature.clone(),
            });
        }

        self.busy_state.last_sample_ns = window_end_ns;
        self.busy_state.last_pids = result.iter().map(|r| r.pid).collect();

        Ok(result)
    }

    /// Borrow the internal NVML scratch buffer after refilling it from
    /// `nvmlDeviceGetComputeRunningProcesses_v3`. The returned slice aliases
    /// `self.compute_scratch` and is invalidated by the next call, so this
    /// stays private; public consumers copy out via [`list_compute_processes`]
    /// or [`attribute_window`].
    fn sample_compute_processes(&mut self) -> Result<&[NvmlProcessInfoV3]> {
        loop {
            let mut count: c_uint = self.compute_scratch.capacity() as c_uint;
            // SAFETY: passing a writable pointer into NVML; capacity matches
            // the buffer we allocated. NVML writes `count` items on success
            // or returns NVML_ERROR_INSUFFICIENT_SIZE with the required count.
            let code = unsafe {
                nvmlDeviceGetComputeRunningProcesses_v3(
                    self.device_handle,
                    &mut count,
                    self.compute_scratch.as_mut_ptr(),
                )
            };

            // NVML returns NVML_ERROR_INSUFFICIENT_SIZE with the required
            // count when our buffer is too small.
            if code == NVML_ERROR_INSUFFICIENT_SIZE {
                self.compute_scratch
                    .reserve(count as usize - self.compute_scratch.capacity());
                continue;
            }
            check_nvml(code, "nvmlDeviceGetComputeRunningProcesses_v3")?;

            // SAFETY: NVML wrote `count` valid `NvmlProcessInfoV3` records
            // into the buffer.
            unsafe {
                self.compute_scratch.set_len(count as usize);
            }
            return Ok(self.compute_scratch.as_slice());
        }
    }
}

impl Drop for WindowsProvider {
    fn drop(&mut self) {
        // We deliberately do *not* call nvmlShutdown here: the daemon process
        // may host many providers across many devices and only the last one
        // standing should shut NVML down. Operators do that in their main()
        // loop instead.
    }
}

impl EnergyProvider for WindowsProvider {
    fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
        let power_uw = self.read_power_uw()?;
        let observed_at_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        )
        .unwrap_or(u64::MAX);

        // Refresh the active compute-process set so that callers using the
        // default `start_sampling_loop` (which only invokes
        // `sample_power_state` + `active_pids`) see real NVML compute PIDs
        // instead of an empty list — otherwise the loop would fan all energy
        // onto PID 0 even while real workloads are running.
        match self.sample_compute_processes() {
            Ok(procs) => {
                self.busy_state.last_pids = procs.iter().map(|p| p.pid).collect();
                self.busy_state.last_sample_ns = observed_at_ns;
            }
            Err(err) => {
                warn!(
                    "WindowsProvider[{}]::sample_power_state compute-process refresh failed: {err}",
                    self.device_index
                );
            }
        }

        Ok(PowerSnapshot {
            observed_at_ns,
            idle_power_uw: 0,
            active_power_uw: power_uw,
            cpu_power_uw: 0,
            gpu_power_uw: power_uw,
            accelerator_power_uw: power_uw,
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
            "WindowsProvider[{}]::sync_registry pushed {total} µJ",
            self.device_index
        );
        Ok(total)
    }

    fn hardware_signature(&self) -> &str {
        &self.hardware_signature
    }

    fn active_pids(&self) -> Vec<u32> {
        // Surfaced from the most recent compute-process snapshot — the
        // differential sampling loop reads this to fan a 100 ms Δ across
        // the right PIDs without re-querying NVML.
        self.busy_state.last_pids.clone()
    }
}

fn read_nvml_serial(handle: NvmlDeviceT) -> Result<String> {
    let mut buf = MaybeUninit::<[c_char; NVML_DEVICE_SERIAL_BUFFER_SIZE]>::uninit();
    // SAFETY: NVML writes up to `length` bytes into `buf`.
    let code = unsafe {
        nvmlDeviceGetSerial(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            NVML_DEVICE_SERIAL_BUFFER_SIZE as c_uint,
        )
    };
    check_nvml(code, "nvmlDeviceGetSerial")?;
    // SAFETY: NVML guarantees a NUL-terminated string on success.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    Ok(cstr.to_string_lossy().into_owned())
}

fn read_nvml_uuid(handle: NvmlDeviceT) -> Result<String> {
    let mut buf = MaybeUninit::<[c_char; NVML_DEVICE_UUID_BUFFER_SIZE]>::uninit();
    // SAFETY: NVML writes up to `length` bytes into `buf`.
    let code = unsafe {
        nvmlDeviceGetUUID(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            NVML_DEVICE_UUID_BUFFER_SIZE as c_uint,
        )
    };
    check_nvml(code, "nvmlDeviceGetUUID")?;
    // SAFETY: NVML guarantees a NUL-terminated string on success.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    Ok(cstr.to_string_lossy().into_owned())
}
