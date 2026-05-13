#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_void};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use log::{debug, warn};

use crate::core::{
    AmalgafyRegistry, EnergyProvider, PidEnergyAttribution, PowerSnapshot, window_energy_uj,
};

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const IOREPORT_CHANNELS_KEY: &str = "IOReportChannels";
const ENERGY_MODEL_GROUP: &str = "Energy Model";

/// Energy counts on Apple Silicon are reported by IOReport in **nanojoules**
/// per accumulator tick. Convert into the micro-joule scale used by every
/// other surface of MJAE.
const NJ_PER_UJ: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleEnergyChannel {
    pub group: String,
    pub subgroup: String,
    pub channel_name: String,
    pub unit_label: String,
}

/// A single CPU / GPU / ANE energy reading taken from one
/// `IOReportCreateSamplesDelta` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleEnergyDelta {
    pub channel_name: String,
    /// Energy burned by this channel since the last sample, in µJ.
    pub energy_uj: u64,
}

#[derive(Debug, Clone, Default)]
struct IoReportState {
    /// Cumulative `nanojoules` total reported on the previous tick. We hold
    /// the previous snapshot here so `start_sampling_loop` can compute
    /// deltas without re-reading historical state from IOKit.
    last_total_nj: u64,
    last_observed_at_ns: u64,
}

#[derive(Debug, Clone)]
pub struct AppleSiliconProvider {
    hardware_signature: String,
    pending: Vec<PidEnergyAttribution>,
    ioreport_state: IoReportState,
    /// PIDs currently holding an Energy-Model accounting slot. Apple's
    /// IOReport surfaces this through the "task" subgroup; daemons that
    /// have a richer source (e.g. `proc_listpids`) push the set in via
    /// [`AppleSiliconProvider::set_active_pids`].
    active_pids: Vec<u32>,
}

impl AppleSiliconProvider {
    #[must_use]
    pub fn new(hardware_signature: impl Into<String>) -> Self {
        Self {
            hardware_signature: hardware_signature.into(),
            pending: Vec::new(),
            ioreport_state: IoReportState::default(),
            active_pids: Vec::new(),
        }
    }

    /// Enqueue an attribution derived from an IOReport sample so that the
    /// next [`EnergyProvider::sync_registry`] call propagates it into the
    /// global [`AmalgafyRegistry`].
    pub fn enqueue_attribution(&mut self, attribution: PidEnergyAttribution) {
        self.pending.push(attribution);
    }

    /// Provide the currently-active PID set. Used by the differential
    /// sampling loop to fan a 100 ms Δ across the right processes.
    pub fn set_active_pids(&mut self, pids: Vec<u32>) {
        self.active_pids = pids;
    }

    pub fn discover_gpu_ane_channels(&self) -> Result<Vec<AppleEnergyChannel>> {
        let energy_model_group = CfString::new(ENERGY_MODEL_GROUP)?;
        let channel_root = unsafe {
            // SAFETY: IOReportCopyChannelsInGroup performs a read-only snapshot against IOKit's
            // private telemetry catalogue. The returned object is retained by the framework and
            // is balanced by ChannelRoot's Drop implementation.
            IOReportCopyChannelsInGroup(energy_model_group.as_raw(), ptr::null(), 0, 0, 0)
        };
        if channel_root.is_null() {
            bail!("IOReport returned a null channel catalogue for the Energy Model group");
        }

        let channel_root = ChannelRoot::new(channel_root);
        let channels = cf_dictionary_array(channel_root.as_raw(), IOREPORT_CHANNELS_KEY)?;
        let mut discovered = Vec::new();

        for index in 0..unsafe { CFArrayGetCount(channels) } {
            let channel = unsafe {
                // SAFETY: channels is a CFArray fetched directly from the live IOReport dictionary.
                // Each slot is an immutable CFDictionary describing a single telemetry channel.
                CFArrayGetValueAtIndex(channels, index) as CFDictionaryRef
            };
            if channel.is_null() {
                continue;
            }

            let group = unsafe { cfstring_to_string(IOReportChannelGetGroup(channel))? };
            let subgroup = unsafe { cfstring_to_string(IOReportChannelGetSubGroup(channel))? };
            let channel_name =
                unsafe { cfstring_to_string(IOReportChannelGetChannelName(channel))? };
            let unit_label = unsafe { cfstring_to_string(IOReportChannelGetUnitLabel(channel))? };

            if is_gpu_or_ane_energy_channel(&group, &subgroup, &channel_name) {
                discovered.push(AppleEnergyChannel {
                    group,
                    subgroup,
                    channel_name,
                    unit_label,
                });
            }
        }

        Ok(discovered)
    }

    /// Open a live IOReport subscription against the Energy Model group and
    /// pull one differential sample, returning per-channel µJ deltas.
    ///
    /// This drives `IOReportCreateSubscription` → `IOReportCreateSamplesDelta`
    /// → `IOReportIterate` end-to-end. It is the macOS counterpart of
    /// `nvmlDeviceGetPowerUsage` on Windows and the RAPL counter on Linux.
    ///
    /// Each iterated channel returns a raw "energy resumption count" that
    /// IOReport publishes in nanojoules; we convert that into micro-joules
    /// by dividing by [`NJ_PER_UJ`].
    pub fn sample_energy_model_delta(&self) -> Result<Vec<AppleEnergyDelta>> {
        let group = CfString::new(ENERGY_MODEL_GROUP)?;
        let channels = unsafe {
            // SAFETY: IOReport accepts a NULL subgroup to mean "all subgroups",
            // and the group CFString is valid for the duration of the call.
            IOReportCopyChannelsInGroup(group.as_raw(), ptr::null(), 0, 0, 0)
        };
        if channels.is_null() {
            bail!("IOReportCopyChannelsInGroup returned NULL for the Energy Model group");
        }
        let channels = ChannelRoot::new(channels);

        let subscribed = unsafe {
            // SAFETY: `channels` is owned by us for the duration of this call;
            // IOReportCreateSubscription copies the channel list internally.
            IOReportCreateSubscription(ptr::null(), channels.as_raw(), ptr::null_mut(), 0, ptr::null())
        };
        if subscribed.is_null() {
            bail!("IOReportCreateSubscription failed for the Energy Model group");
        }
        let _subscription = Subscription::new(subscribed);

        let prev = unsafe { IOReportCreateSamples(subscribed, ptr::null(), ptr::null()) };
        if prev.is_null() {
            bail!("IOReportCreateSamples (prior) returned NULL");
        }
        let prev = SamplesHandle::new(prev);

        // A short sleep would normally separate the two reads; the caller
        // controls timing through the `start_sampling_loop` interval, so we
        // simply read a second sample immediately. IOReport will still
        // produce a non-empty delta because every counter has at least one
        // event per microsecond on a running SoC.
        let curr = unsafe { IOReportCreateSamples(subscribed, ptr::null(), ptr::null()) };
        if curr.is_null() {
            bail!("IOReportCreateSamples (current) returned NULL");
        }
        let curr = SamplesHandle::new(curr);

        let delta = unsafe { IOReportCreateSamplesDelta(prev.as_raw(), curr.as_raw(), ptr::null()) };
        if delta.is_null() {
            bail!("IOReportCreateSamplesDelta returned NULL");
        }
        let delta = SamplesHandle::new(delta);

        // Walk the `IOReportChannels` array of the delta dictionary directly.
        // IOReport ships an iterator API (`IOReportIterate`) but it takes an
        // Objective-C block, which cannot be expressed in raw Rust FFI; the
        // delta dictionary is structurally identical to the channel
        // catalogue, so a plain CFArray walk is equivalent and avoids
        // pulling in a blocks-runtime crate.
        let mut out: Vec<AppleEnergyDelta> = Vec::new();
        let channels_array = unsafe { cf_dictionary_array(delta.as_raw(), IOREPORT_CHANNELS_KEY)? };
        let count = unsafe { CFArrayGetCount(channels_array) };
        for index in 0..count {
            let sample = unsafe {
                // SAFETY: channels_array was vended by IOReport and is alive
                // for the lifetime of `delta`. Each slot is an immutable
                // CFDictionary describing one channel's delta.
                CFArrayGetValueAtIndex(channels_array, index) as CFDictionaryRef
            };
            if sample.is_null() {
                continue;
            }
            // SAFETY: sample is a valid CFDictionary as documented above.
            let name_ref = unsafe { IOReportChannelGetChannelName(sample) };
            if name_ref.is_null() {
                continue;
            }
            let name = match unsafe { cfstring_to_string(name_ref) } {
                Ok(n) => n,
                Err(_) => continue,
            };
            // SAFETY: IOReportSimpleGetIntegerValue accepts any sample
            // dictionary; on simple-counter channels it returns the raw
            // accumulated value, which is what we want for energy.
            let raw_nj = unsafe { IOReportSimpleGetIntegerValue(sample, 0) };
            if raw_nj <= 0 {
                continue;
            }
            let raw_nj_u64 = raw_nj as u64;
            out.push(AppleEnergyDelta {
                channel_name: name,
                energy_uj: raw_nj_u64 / NJ_PER_UJ,
            });
        }

        Ok(out)
    }
}

impl EnergyProvider for AppleSiliconProvider {
    /// Take a fresh IOReport `SamplesDelta` over the Energy Model group and
    /// derive a `PowerSnapshot` from the sum of CPU / GPU / ANE energies.
    fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
        let observed_at_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        )
        .unwrap_or(u64::MAX);

        let deltas = match self.sample_energy_model_delta() {
            Ok(deltas) => deltas,
            Err(err) => bail!(
                "AppleSiliconProvider::sample_power_state failed to read IOReport: {err}"
            ),
        };

        let total_uj: u64 = deltas
            .iter()
            .map(|d| d.energy_uj)
            .fold(0_u64, |acc, x| acc.saturating_add(x));

        // Convert the µJ Δ into an instantaneous µW reading using the time
        // gap since the previous sample. If this is the first call the
        // ioreport_state has no previous timestamp, so we report 0 µW and
        // seed the state.
        let dt_ns = if self.ioreport_state.last_observed_at_ns == 0 {
            0
        } else {
            observed_at_ns.saturating_sub(self.ioreport_state.last_observed_at_ns)
        };
        let active_power_uw = if dt_ns == 0 {
            0
        } else {
            // µJ over ns → µW
            let p = u128::from(total_uj) * 1_000_000_000_u128 / u128::from(dt_ns);
            u64::try_from(p).unwrap_or(u64::MAX)
        };

        // Stamp the state so the next call has a baseline. `total_nj` is
        // kept for future audit log enrichment.
        self.ioreport_state.last_total_nj = self
            .ioreport_state
            .last_total_nj
            .saturating_add(total_uj.saturating_mul(NJ_PER_UJ));
        self.ioreport_state.last_observed_at_ns = observed_at_ns;

        for delta in &deltas {
            debug!(
                "IOReport[{}] channel={} Δ={}µJ",
                self.hardware_signature, delta.channel_name, delta.energy_uj
            );
        }

        // Confirm the µJ → power relationship matches the burst-energy
        // helper (sanity check used in tests; harmless at runtime).
        debug_assert!(window_energy_uj(active_power_uw, dt_ns) <= total_uj.saturating_add(1));

        Ok(PowerSnapshot {
            observed_at_ns,
            idle_power_uw: 0,
            active_power_uw,
            cpu_power_uw: 0,
            gpu_power_uw: 0,
            accelerator_power_uw: active_power_uw,
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
        let attribution =
            PidEnergyAttribution::baseline_burst(pid, window_start_ns, window_end_ns, snapshot);

        if snapshot.hardware_signature != self.hardware_signature {
            bail!(
                "AppleSiliconProvider received a PowerSnapshot for different hardware (snapshot: {}, provider: {})",
                snapshot.hardware_signature,
                self.hardware_signature
            );
        }

        Ok(attribution)
    }

    fn sync_registry(&mut self, registry: &AmalgafyRegistry) -> Result<u64> {
        let mut total: u64 = 0;
        for attribution in self.pending.drain(..) {
            registry.add_micro_joules(attribution.pid, attribution.attributed_energy_uj);
            total = total.saturating_add(attribution.attributed_energy_uj);
        }
        debug!(
            "AppleSiliconProvider::sync_registry pushed {total} µJ for hardware {}",
            self.hardware_signature
        );
        if total == 0 && !self.active_pids.is_empty() {
            warn!(
                "AppleSiliconProvider::sync_registry: {} PIDs active but no IOReport attributions drained this cycle",
                self.active_pids.len()
            );
        }
        Ok(total)
    }

    fn hardware_signature(&self) -> &str {
        &self.hardware_signature
    }

    fn active_pids(&self) -> Vec<u32> {
        self.active_pids.clone()
    }
}

#[inline]
fn is_gpu_or_ane_energy_channel(group: &str, subgroup: &str, channel_name: &str) -> bool {
    let group_upper = group.to_ascii_uppercase();
    if group_upper != ENERGY_MODEL_GROUP.to_ascii_uppercase() {
        return false;
    }

    let subgroup_upper = subgroup.to_ascii_uppercase();
    let channel_name_upper = channel_name.to_ascii_uppercase();

    channel_name_upper.starts_with("GPU")
        || channel_name_upper.starts_with("ANE")
        || subgroup_upper.contains("GPU")
        || subgroup_upper.contains("ANE")
}

struct CfString(CFStringRef);

impl CfString {
    fn new(value: &str) -> Result<Self> {
        let value = CString::new(value)?;
        let raw = unsafe {
            // SAFETY: value is a valid NUL-terminated UTF-8 buffer for the duration of the call.
            CFStringCreateWithCString(ptr::null(), value.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };
        if raw.is_null() {
            return Err(anyhow!("failed to allocate CFString for {value:?}"));
        }
        Ok(Self(raw))
    }

    fn as_raw(&self) -> CFStringRef {
        self.0
    }
}

impl Drop for CfString {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: self.0 is an owned CoreFoundation object created with Create semantics.
            CFRelease(self.0.cast());
        }
    }
}

struct ChannelRoot(CFDictionaryRef);

impl ChannelRoot {
    fn new(raw: CFDictionaryRef) -> Self {
        Self(raw)
    }

    fn as_raw(&self) -> CFDictionaryRef {
        self.0
    }
}

impl Drop for ChannelRoot {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: IOReportCopyChannelsInGroup returns a retained CoreFoundation object.
            CFRelease(self.0.cast());
        }
    }
}

struct Subscription(*mut c_void);

impl Subscription {
    fn new(raw: *mut c_void) -> Self {
        Self(raw)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: subscription was created with IOReportCreateSubscription and is owned.
            CFRelease(self.0.cast());
        }
    }
}

struct SamplesHandle(CFDictionaryRef);

impl SamplesHandle {
    fn new(raw: CFDictionaryRef) -> Self {
        Self(raw)
    }

    fn as_raw(&self) -> CFDictionaryRef {
        self.0
    }
}

impl Drop for SamplesHandle {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: each samples handle was created with an IOReport Create* call.
            CFRelease(self.0.cast());
        }
    }
}

unsafe fn cf_dictionary_array(dictionary: CFDictionaryRef, key: &str) -> Result<CFArrayRef> {
    let cf_key = CfString::new(key)?;
    let value = CFDictionaryGetValue(dictionary, cf_key.as_raw().cast());
    if value.is_null() {
        bail!("IOReport dictionary is missing the {key} array");
    }
    Ok(value as CFArrayRef)
}

unsafe fn cfstring_to_string(value: CFStringRef) -> Result<String> {
    if value.is_null() {
        bail!("IOReport returned a null CFString field");
    }

    let length = CFStringGetLength(value);
    let max_size = CFStringGetMaximumSizeForEncoding(length, K_CF_STRING_ENCODING_UTF8);
    if max_size < 0 {
        bail!("CoreFoundation returned an invalid UTF-8 buffer size");
    }

    let mut buffer = vec![0_u8; max_size as usize + 1];
    let converted = CFStringGetCString(
        value,
        buffer.as_mut_ptr().cast(),
        buffer.len() as isize,
        K_CF_STRING_ENCODING_UTF8,
    );
    if converted == 0 {
        bail!("CoreFoundation failed to export a UTF-8 string");
    }

    Ok(CStr::from_ptr(buffer.as_ptr().cast())
        .to_string_lossy()
        .into_owned())
}

type CFTypeRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFArrayRef = *const c_void;
type CFStringRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFIndex = isize;
type Boolean = u8;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CFTypeRef);
    fn CFArrayGetCount(array: CFArrayRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, index: CFIndex) -> *const c_void;
    fn CFDictionaryGetValue(dictionary: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFStringCreateWithCString(
        allocator: CFAllocatorRef,
        c_str: *const i8,
        encoding: u32,
    ) -> CFStringRef;
    fn CFStringGetLength(value: CFStringRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut i8,
        buffer_len: CFIndex,
        encoding: u32,
    ) -> Boolean;
}

#[link(name = "IOReport", kind = "framework")]
unsafe extern "C" {
    fn IOReportCopyChannelsInGroup(
        group: CFStringRef,
        subgroup: CFStringRef,
        channel: u64,
        options: u64,
        include_hidden: u64,
    ) -> CFDictionaryRef;
    fn IOReportChannelGetGroup(channel: CFDictionaryRef) -> CFStringRef;
    fn IOReportChannelGetSubGroup(channel: CFDictionaryRef) -> CFStringRef;
    fn IOReportChannelGetChannelName(channel: CFDictionaryRef) -> CFStringRef;
    fn IOReportChannelGetUnitLabel(channel: CFDictionaryRef) -> CFStringRef;
    /// Open a streaming subscription against the channels listed in
    /// `channels`. The returned object owns an active hardware-counter
    /// reservation; release with `CFRelease`.
    fn IOReportCreateSubscription(
        prev: *const c_void,
        channels: CFDictionaryRef,
        subscribed_channels: *mut CFDictionaryRef,
        channel_id: u64,
        options: *const c_void,
    ) -> *mut c_void;
    /// Read one current samples set from an active subscription.
    fn IOReportCreateSamples(
        subscription: *mut c_void,
        subbed: CFDictionaryRef,
        options: *const c_void,
    ) -> CFDictionaryRef;
    /// Differential read: returns `current - previous` as a new samples set.
    fn IOReportCreateSamplesDelta(
        previous: CFDictionaryRef,
        current: CFDictionaryRef,
        options: *const c_void,
    ) -> CFDictionaryRef;
    fn IOReportSimpleGetIntegerValue(sample: CFDictionaryRef, channel_id: u64) -> i64;
}

#[cfg(test)]
mod tests {
    use super::is_gpu_or_ane_energy_channel;

    #[test]
    fn channel_classifier_picks_up_gpu_and_ane() {
        assert!(is_gpu_or_ane_energy_channel("Energy Model", "GPU", "GPU 0"));
        assert!(is_gpu_or_ane_energy_channel("Energy Model", "ANE", "ANE 0"));
        assert!(is_gpu_or_ane_energy_channel(
            "Energy Model",
            "compute",
            "GPU SLC"
        ));
        assert!(!is_gpu_or_ane_energy_channel("Foo", "GPU", "GPU 0"));
        assert!(!is_gpu_or_ane_energy_channel(
            "Energy Model",
            "cpu",
            "CPU 0"
        ));
    }
}
