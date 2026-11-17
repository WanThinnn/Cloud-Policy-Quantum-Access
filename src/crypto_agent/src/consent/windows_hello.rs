use windows::{
    core::{factory, HSTRING},
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::{
        System::WinRT::{
            IUserConsentVerifierInterop, RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED,
        },
        UI::WindowsAndMessaging::{GetClassNameW, GetForegroundWindow},
    },
};
use windows_future::IAsyncOperation;

const UNAVAILABLE: &str = "os_verification_unavailable";

// Native Messaging starts a fresh process. Keep WinRT initialized until every
// verification object on this thread has been released.
struct Runtime;

impl Runtime {
    fn initialize() -> Result<Self, &'static str> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|_| UNAVAILABLE)?;
        Ok(Self)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

fn available() -> Result<(), &'static str> {
    let status = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.join())
        .map_err(|_| UNAVAILABLE)?;
    match status {
        UserConsentVerifierAvailability::Available => Ok(()),
        UserConsentVerifierAvailability::DeviceBusy => Err("os_verification_busy"),
        _ => Err(UNAVAILABLE),
    }
}

pub fn check_availability() -> Result<(), &'static str> {
    let _runtime = Runtime::initialize()?;
    available()
}

fn verification_result(result: UserConsentVerificationResult) -> Result<(), &'static str> {
    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => Err("os_verification_cancelled"),
        UserConsentVerificationResult::RetriesExhausted => Err("os_verification_denied"),
        UserConsentVerificationResult::DeviceBusy => Err("os_verification_busy"),
        _ => Err(UNAVAILABLE),
    }
}

pub fn confirm(message: &str) -> Result<(), &'static str> {
    let _runtime = Runtime::initialize()?;
    available()?;
    // Chromium sends a null parent HWND to hosts started by a service worker.
    // Anchor the system prompt to the foreground Chromium window, or fail closed.
    let owner = unsafe { GetForegroundWindow() };
    let mut class_name = [0u16; 64];
    let size = unsafe { GetClassNameW(owner, &mut class_name) };
    if size <= 0
        || !String::from_utf16_lossy(&class_name[..size as usize]).starts_with("Chrome_WidgetWin_")
    {
        return Err("os_verification_browser_focus");
    }
    let interop =
        factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(|_| UNAVAILABLE)?;
    let operation: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(owner, &HSTRING::from(message)) }
            .map_err(|_| UNAVAILABLE)?;
    verification_result(operation.join().map_err(|_| UNAVAILABLE)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_verified_allows_a_signing_operation() {
        assert_eq!(
            verification_result(UserConsentVerificationResult::Verified),
            Ok(())
        );
        assert_eq!(
            verification_result(UserConsentVerificationResult::Canceled),
            Err("os_verification_cancelled")
        );
        assert!(verification_result(UserConsentVerificationResult::RetriesExhausted).is_err());
        assert!(verification_result(UserConsentVerificationResult::DeviceNotPresent).is_err());
        assert!(verification_result(UserConsentVerificationResult(999)).is_err());
    }
}
