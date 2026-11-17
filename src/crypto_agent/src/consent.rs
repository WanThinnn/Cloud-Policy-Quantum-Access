#[cfg(windows)]
mod windows_hello;

#[cfg(windows)]
pub use windows_hello::{check_availability, confirm};

#[cfg(not(windows))]
pub fn check_availability() -> Result<(), &'static str> {
    Err("os_verification_unsupported")
}
#[cfg(not(windows))]
pub fn confirm(_message: &str) -> Result<(), &'static str> {
    check_availability()
}
