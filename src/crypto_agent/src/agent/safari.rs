use super::{dispatch, response, Config, Upstream, MAX_MESSAGE};
use std::{
    ffi::{c_char, CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    path::Path,
    slice,
    sync::OnceLock,
};

/// Safari's native extension passes a JSON frame and paths in its signed bundle.
/// The caller owns the frame and path buffers until this function returns.
#[no_mangle]
pub unsafe extern "C" fn cpqa_safari_handle_request(
    data: *const u8,
    length: usize,
    config_path: *const c_char,
    library_path: *const c_char,
) -> *mut c_char {
    let result = if data.is_null() || length == 0 || length > MAX_MESSAGE {
        Err("invalid_frame")
    } else if config_path.is_null() || library_path.is_null() {
        Err("invalid_installation")
    } else {
        let config = unsafe { CStr::from_ptr(config_path) };
        let library = unsafe { CStr::from_ptr(library_path) };
        let frame = unsafe { slice::from_raw_parts(data, length) };
        Config::read(Path::new(OsStr::from_bytes(config.to_bytes()))).and_then(|config| {
            dispatch(&config, frame, || {
                // Safari keeps the native extension process alive between requests.
                static RUNTIME: OnceLock<Result<Upstream, &'static str>> = OnceLock::new();
                RUNTIME
                    .get_or_init(|| {
                        Upstream::load_at(Path::new(OsStr::from_bytes(library.to_bytes())))
                    })
                    .as_ref()
                    .map_err(|error| *error)
            })
        })
    };
    CString::new(response(result).to_string()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Release the response allocated by cpqa_safari_handle_request exactly once.
#[no_mangle]
pub unsafe extern "C" fn cpqa_safari_free_response(data: *mut c_char) {
    if !data.is_null() {
        drop(unsafe { CString::from_raw(data) });
    }
}
