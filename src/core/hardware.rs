//! Hardware Identity probing.
//!
//! Every signed [`AmalgafySeal`](crate::core::signer::AmalgafySeal) is bound
//! to a hardware fingerprint so an attacker cannot replay one machine's
//! manifest as another's ("Audit Spoofing"). The fingerprint is a stable,
//! per-host identifier derived from kernel- or firmware-level telemetry:
//!
//! * **macOS** — the SoC's `IOPlatformSerialNumber` published by IOKit's
//!   `IOPlatformExpertDevice` registry entry.
//! * **Linux** — `/etc/machine-id` (systemd-managed, stable across reboots),
//!   with a sysfs GPU UUID fallback for diskless / immutable images.
//! * **Windows** — the NVML device serial returned by `nvmlDeviceGetSerial`,
//!   with `nvmlDeviceGetUUID` as a fallback when the serial is unavailable
//!   (e.g. on some consumer GPUs).
//!
//! All three paths return a non-empty UTF-8 string. The probe never panics
//! on partial telemetry — it falls back to a process-stable synthetic ID and
//! records a warning so operators can see in the logs that the host is
//! missing a real fingerprint source.
//!
//! The fingerprint is intentionally stringly-typed: it goes straight into
//! canonical JSON and gets sealed into the Ed25519 signature, so the
//! representation has to be deterministic on a given host but not opaque to
//! humans reading a manifest.

use std::fmt;

use anyhow::Result;
use log::warn;
use serde::{Deserialize, Serialize};

/// A stable identifier for the physical machine producing a manifest.
///
/// `HardwareIdentity` values are `Clone`-able and `Serialize`-able so they
/// can be embedded into an [`AmalgafySealPayload`](crate::core::signer::AmalgafySealPayload)
/// without ceremony. The `source` field records *how* the identity was
/// obtained so auditors can distinguish "real, kernel-confirmed serial" from
/// "synthetic fallback" without having to parse the value string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareIdentity {
    /// The fingerprint itself, in a human-readable form (UUID, machine-id,
    /// SoC serial, etc.).
    pub fingerprint: String,
    /// Where the fingerprint came from. Surfaced to auditors verifying a
    /// seal so they can see whether the daemon found a real identity probe
    /// or had to fall back.
    pub source: HardwareIdentitySource,
}

/// Describes which probe produced a [`HardwareIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareIdentitySource {
    /// macOS IOKit `IOPlatformSerialNumber`.
    MacosIoKitSerial,
    /// Linux `/etc/machine-id`.
    LinuxMachineId,
    /// Linux GPU UUID surfaced via `/sys/class/drm/*/device`.
    LinuxGpuUuid,
    /// Windows NVML `nvmlDeviceGetUUID` (used as a fallback when the device
    /// serial is unavailable).
    WindowsNvmlUuid,
    /// Windows NVML `nvmlDeviceGetSerial` (preferred Windows fingerprint).
    WindowsNvmlSerial,
    /// Caller-supplied identity (tests, CI, hand-rolled daemons).
    Manual,
    /// No probe succeeded; the daemon synthesised a placeholder so the
    /// seal still has *some* value bound to it. Auditors should treat
    /// seals with this source as unverifiable.
    Synthetic,
}

impl fmt::Display for HardwareIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (source: {:?})", self.fingerprint, self.source)
    }
}

impl HardwareIdentity {
    /// Construct a manually supplied identity (tests, daemons that already
    /// know their serial from a different probe).
    #[must_use]
    pub fn manual(fingerprint: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            source: HardwareIdentitySource::Manual,
        }
    }

    /// Construct a synthetic placeholder identity. Use this only when every
    /// real probe has failed — auditors are expected to flag any seal whose
    /// `source == Synthetic`.
    ///
    /// The returned fingerprint embeds a host- and process-specific
    /// component so two distinct hosts (or two daemons on the same host)
    /// that both fall back to synthetic still produce different identities;
    /// this preserves the per-host binding contract even when no real
    /// kernel/firmware source is available.
    #[must_use]
    pub fn synthetic(reason: impl Into<String>) -> Self {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()))
            .unwrap_or_else(|_| "unknown-host".to_owned());
        let host = host.trim();
        let host = if host.is_empty() {
            "unknown-host"
        } else {
            host
        };
        let pid = std::process::id();
        Self {
            fingerprint: format!("synthetic:{}:host={}:pid={}", reason.into(), host, pid),
            source: HardwareIdentitySource::Synthetic,
        }
    }

    /// Probe the host for its best available fingerprint.
    ///
    /// The probe is OS-gated:
    /// * On macOS we read `IOPlatformSerialNumber` via IOKit.
    /// * On Linux we read `/etc/machine-id`, falling back to the first
    ///   readable `uuid` attribute under `/sys/class/drm/`.
    /// * On Windows we initialise NVML and read `nvmlDeviceGetSerial` for
    ///   device 0, falling back to `nvmlDeviceGetUUID` (multi-GPU daemons
    ///   can probe other devices through
    ///   [`HardwareIdentity::probe_windows_device`]).
    ///
    /// Any failure is logged and the function returns a synthetic identity
    /// instead of erroring — the daemon must not crash because a host is
    /// missing one telemetry source.
    #[must_use]
    pub fn probe() -> Self {
        match Self::try_probe() {
            Ok(identity) => identity,
            Err(err) => {
                warn!("HardwareIdentity probe failed, using synthetic fallback: {err}");
                Self::synthetic("probe_failed")
            }
        }
    }

    /// Fallible variant of [`HardwareIdentity::probe`]. Callers that want to
    /// surface probe errors (e.g. an installer that refuses to enrol a host
    /// it cannot identify) use this form.
    pub fn try_probe() -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            macos::probe()
        }
        #[cfg(target_os = "linux")]
        {
            linux::probe()
        }
        #[cfg(target_os = "windows")]
        {
            windows::probe_device(0)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            anyhow::bail!("HardwareIdentity probe is not implemented on this OS")
        }
    }

    /// Windows-specific helper: probe a *specific* NVIDIA device by index.
    /// Only available when compiled for Windows; on other targets the function
    /// is not defined.
    #[cfg(target_os = "windows")]
    pub fn probe_windows_device(device_index: u32) -> Result<Self> {
        windows::probe_device(device_index)
    }
}

// ---------------------------------------------------------------------------
// Linux probe
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};

    use super::{HardwareIdentity, HardwareIdentitySource};

    pub(super) fn probe() -> Result<HardwareIdentity> {
        match read_machine_id() {
            Ok(id) => Ok(HardwareIdentity {
                fingerprint: id,
                source: HardwareIdentitySource::LinuxMachineId,
            }),
            Err(machine_err) => match read_gpu_uuid() {
                Ok(uuid) => Ok(HardwareIdentity {
                    fingerprint: uuid,
                    source: HardwareIdentitySource::LinuxGpuUuid,
                }),
                Err(gpu_err) => {
                    bail!(
                        "/etc/machine-id unreadable ({machine_err}) and no GPU UUID under /sys/class/drm/* ({gpu_err})"
                    )
                }
            },
        }
    }

    fn read_machine_id() -> Result<String> {
        let raw =
            fs::read_to_string("/etc/machine-id").context("failed to read /etc/machine-id")?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("/etc/machine-id is empty");
        }
        Ok(trimmed.to_owned())
    }

    fn read_gpu_uuid() -> Result<String> {
        let entries =
            fs::read_dir("/sys/class/drm").context("failed to enumerate /sys/class/drm")?;
        for entry in entries.flatten() {
            let mut candidate: PathBuf = entry.path();
            candidate.push("device");
            candidate.push("uuid");
            if let Ok(raw) = fs::read_to_string(&candidate) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_owned());
                }
            }
        }
        bail!("no GPU UUID found in any /sys/class/drm/*/device/uuid file")
    }
}

// ---------------------------------------------------------------------------
// macOS probe
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    use std::ptr;

    use anyhow::{Result, anyhow, bail};

    use super::{HardwareIdentity, HardwareIdentitySource};

    const K_IO_MASTER_PORT_DEFAULT: u32 = 0;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_IO_RETURN_SUCCESS: c_int = 0;

    type IoRegistryEntryT = u32;
    type IoObjectT = u32;
    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFIndex = isize;
    type Boolean = u8;

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceMatching(name: *const c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(master_port: u32, matching: *mut c_void)
        -> IoRegistryEntryT;
        fn IORegistryEntryCreateCFProperty(
            entry: IoRegistryEntryT,
            key: CFStringRef,
            allocator: CFAllocatorRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: IoObjectT) -> c_int;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: CFTypeRef);
        fn CFStringCreateWithCString(
            allocator: CFAllocatorRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFStringGetLength(value: CFStringRef) -> CFIndex;
        fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
        fn CFStringGetCString(
            value: CFStringRef,
            buffer: *mut c_char,
            buffer_len: CFIndex,
            encoding: u32,
        ) -> Boolean;
    }

    pub(super) fn probe() -> Result<HardwareIdentity> {
        let serial = read_platform_serial()?;
        Ok(HardwareIdentity {
            fingerprint: serial,
            source: HardwareIdentitySource::MacosIoKitSerial,
        })
    }

    fn read_platform_serial() -> Result<String> {
        let service_name = CString::new("IOPlatformExpertDevice")
            .map_err(|_| anyhow!("invalid IOKit service name"))?;

        // SAFETY: IOServiceMatching duplicates the input string and is safe to
        // call with any NUL-terminated C string.
        let matching = unsafe { IOServiceMatching(service_name.as_ptr()) };
        if matching.is_null() {
            bail!("IOServiceMatching returned NULL for IOPlatformExpertDevice");
        }

        // IOServiceGetMatchingService *consumes* `matching` — no manual release.
        // SAFETY: master_port = 0 selects the default master port; matching is
        // a valid CFDictionary handed off to IOKit.
        let service = unsafe { IOServiceGetMatchingService(K_IO_MASTER_PORT_DEFAULT, matching) };
        if service == 0 {
            bail!("IOServiceGetMatchingService could not locate IOPlatformExpertDevice");
        }

        let key = CfString::new("IOPlatformSerialNumber")?;
        // SAFETY: `service` is a valid IORegistryEntry and `key.as_raw()` is a
        // valid CFStringRef for the duration of the call.
        let property =
            unsafe { IORegistryEntryCreateCFProperty(service, key.as_raw(), ptr::null(), 0) };

        // Release the service handle as soon as we don't need it anymore.
        // SAFETY: `service` was vended by IOServiceGetMatchingService and is
        // owned by us.
        let release_code = unsafe { IOObjectRelease(service) };
        if release_code != K_IO_RETURN_SUCCESS {
            // Non-fatal; we just leaked a reference. Log via anyhow so the
            // caller's logger surfaces it.
            log::warn!("IOObjectRelease returned non-zero: {release_code}");
        }

        if property.is_null() {
            bail!("IOPlatformSerialNumber property is missing from IOKit registry");
        }

        // SAFETY: `property` is a retained CFString owned by us; convert it
        // into a Rust String and release in the same scope.
        let result = unsafe { cfstring_to_string(property as CFStringRef) };
        unsafe { CFRelease(property) };
        result
    }

    struct CfString(CFStringRef);

    impl CfString {
        fn new(value: &str) -> Result<Self> {
            let value = CString::new(value)
                .map_err(|_| anyhow!("CFString value contains an interior NUL"))?;
            // SAFETY: `value.as_ptr()` is a valid NUL-terminated UTF-8 buffer
            // for the duration of the call.
            let raw = unsafe {
                CFStringCreateWithCString(ptr::null(), value.as_ptr(), K_CF_STRING_ENCODING_UTF8)
            };
            if raw.is_null() {
                bail!("CFStringCreateWithCString returned NULL");
            }
            Ok(Self(raw))
        }

        fn as_raw(&self) -> CFStringRef {
            self.0
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            // SAFETY: self.0 is an owned CoreFoundation object created with
            // CFStringCreateWithCString.
            unsafe { CFRelease(self.0) };
        }
    }

    unsafe fn cfstring_to_string(value: CFStringRef) -> Result<String> {
        if value.is_null() {
            bail!("cfstring_to_string called with NULL");
        }
        let length = CFStringGetLength(value);
        let max_size = CFStringGetMaximumSizeForEncoding(length, K_CF_STRING_ENCODING_UTF8);
        if max_size < 0 {
            bail!("CoreFoundation returned an invalid UTF-8 buffer size");
        }
        let mut buffer = vec![0_u8; max_size as usize + 1];
        let ok = CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast(),
            buffer.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
        );
        if ok == 0 {
            bail!("CFStringGetCString failed to export the serial as UTF-8");
        }
        Ok(CStr::from_ptr(buffer.as_ptr().cast())
            .to_string_lossy()
            .into_owned())
    }
}

// ---------------------------------------------------------------------------
// Windows probe
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use anyhow::Result;

    use super::HardwareIdentity;
    use crate::providers::WindowsProvider;

    pub(super) fn probe_device(device_index: u32) -> Result<HardwareIdentity> {
        // `WindowsProvider::new` exposes its hardware signature using the
        // provider's normal NVML probe order, which prefers the device serial
        // and only falls back to the UUID (and to a synthetic placeholder if
        // both fail). Reuse that path so there is exactly one NVML entry
        // point in the crate, and forward the *actual* source so the seal's
        // identity correctly identifies serial-, UUID-, and synthetic-derived
        // fingerprints.
        let provider = WindowsProvider::new(device_index)?;
        Ok(HardwareIdentity {
            fingerprint: provider.hardware_signature_string(),
            source: provider.signature_source(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{HardwareIdentity, HardwareIdentitySource};

    #[test]
    fn manual_identity_round_trips_through_serde() {
        let id = HardwareIdentity::manual("NV-H100-SXM5-SN-0001");
        assert_eq!(id.source, HardwareIdentitySource::Manual);
        assert_eq!(id.fingerprint, "NV-H100-SXM5-SN-0001");

        let json = serde_json::to_string(&id).expect("identity should serialize");
        let parsed: HardwareIdentity =
            serde_json::from_str(&json).expect("identity should deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn synthetic_identity_is_marked_as_unverifiable() {
        let id = HardwareIdentity::synthetic("no_probe");
        assert_eq!(id.source, HardwareIdentitySource::Synthetic);
        assert!(id.fingerprint.starts_with("synthetic:"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_probe_returns_a_real_or_synthetic_identity() {
        // The probe must never panic and must always yield a non-empty
        // fingerprint, even on hosts that lack /etc/machine-id and a GPU.
        let id = HardwareIdentity::probe();
        assert!(!id.fingerprint.is_empty());
    }
}
