#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_void};
use std::ptr;

use anyhow::{Result, anyhow, bail};

use crate::core::{EnergyProvider, PidEnergyAttribution, PowerSnapshot};

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const IOREPORT_CHANNELS_KEY: &str = "IOReportChannels";
const ENERGY_MODEL_GROUP: &str = "Energy Model";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleEnergyChannel {
    pub group: String,
    pub subgroup: String,
    pub channel_name: String,
    pub unit_label: String,
}

#[derive(Debug, Clone)]
pub struct AppleSiliconProvider {
    hardware_signature: String,
}

impl AppleSiliconProvider {
    #[must_use]
    pub fn new(hardware_signature: impl Into<String>) -> Self {
        Self {
            hardware_signature: hardware_signature.into(),
        }
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
}

impl EnergyProvider for AppleSiliconProvider {
    fn sample_power_state(&mut self) -> Result<PowerSnapshot> {
        bail!(
            "AppleSiliconProvider::sample_power_state requires an active IOReport subscription; only channel discovery is scaffolded in this session"
        )
    }

    fn attribute_joules_to_pid(
        &mut self,
        pid: u32,
        window_start_ns: u64,
        window_end_ns: u64,
        snapshot: &PowerSnapshot,
    ) -> Result<PidEnergyAttribution> {
        let mut attribution =
            PidEnergyAttribution::baseline_burst(pid, window_start_ns, window_end_ns, snapshot);
        attribution.hardware_signature = self.hardware_signature.clone();
        Ok(attribution)
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
        || group_upper.contains("GPU")
        || group_upper.contains("ANE")
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

unsafe fn cf_dictionary_array(dictionary: CFDictionaryRef, key: &str) -> Result<CFArrayRef> {
    let key = CfString::new(key)?;
    let value = CFDictionaryGetValue(dictionary, key.as_raw().cast());
    if value.is_null() {
        bail!("IOReport dictionary is missing the {IOREPORT_CHANNELS_KEY} array");
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
}
