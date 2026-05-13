#[cfg(target_os = "macos")]
mod apple_silicon;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
pub use apple_silicon::AppleSiliconProvider;
#[cfg(target_os = "linux")]
pub use linux::LinuxProvider;
#[cfg(target_os = "windows")]
pub use windows::{NvmlComputeProcess, WindowsProvider};

