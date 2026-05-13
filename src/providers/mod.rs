#[cfg(target_os = "macos")]
mod apple_silicon;
mod linux;

#[cfg(target_os = "macos")]
pub use apple_silicon::AppleSiliconProvider;
pub use linux::LinuxProvider;
