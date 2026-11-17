use libloading::Library;
use std::{env, ffi::c_int, path::Path, ptr, slice, sync::OnceLock};
use zeroize::{Zeroize, Zeroizing};

pub const PUBLIC_BYTES: usize = 2592;
pub const SECRET_BYTES: usize = 4896;
pub const SIGNATURE_BYTES: usize = 4627;

type Keygen = unsafe extern "C" fn(*mut *mut u8, *mut usize, *mut *mut u8, *mut usize) -> c_int;
type Sign = unsafe extern "C" fn(*const u8, usize, *const u8, *mut *mut u8, *mut usize) -> c_int;
type Verify = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8) -> c_int;
type Free = unsafe extern "C" fn(*mut u8);

#[cfg(windows)]
type RuntimeLibrary = std::mem::ManuallyDrop<Library>;
#[cfg(not(windows))]
type RuntimeLibrary = Library;

pub struct Upstream {
    _library: RuntimeLibrary,
    keygen: Keygen,
    sign: Sign,
    verify: Verify,
    free: Free,
}

impl Upstream {
    pub fn load() -> Result<&'static Self, &'static str> {
        static RUNTIME: OnceLock<Result<Upstream, &'static str>> = OnceLock::new();
        RUNTIME
            .get_or_init(Self::load_installed)
            .as_ref()
            .map_err(|error| *error)
    }

    fn load_installed() -> Result<Self, &'static str> {
        let exe = env::current_exe().map_err(|_| "agent_installation_unavailable")?;
        let name = if cfg!(windows) {
            "libhybrid-pq-cp-abe.dll"
        } else if cfg!(target_os = "macos") {
            "libhybrid-pq-cp-abe.dylib"
        } else {
            "libhybrid-pq-cp-abe.so"
        };
        #[cfg(target_os = "macos")]
        if let Some(contents) = crate::agent::mac_app_contents(&exe) {
            return Self::load_at(&contents.join("Frameworks").join(name));
        }
        Self::load_at(&exe.with_file_name(name))
    }

    pub(crate) fn load_at(path: &Path) -> Result<Self, &'static str> {
        // The installer owns this absolute path and its dependencies.
        let library = open(path).map_err(|_| "upstream_library_unavailable")?;
        // On Windows TKN20 embeds Go. FreeLibrary can unmap code while the Go
        // runtime still has live threads, even when only ML-DSA was used.
        #[cfg(windows)]
        let library = RuntimeLibrary::new(library);
        let error = |_| "upstream_abi_unavailable";
        unsafe {
            Ok(Self {
                keygen: *library
                    .get(b"ml_dsa_87_generate_keypair\0")
                    .map_err(error)?,
                sign: *library.get(b"ml_dsa_87_sign\0").map_err(error)?,
                verify: *library.get(b"ml_dsa_87_verify\0").map_err(error)?,
                free: *library.get(b"freeBuffer\0").map_err(error)?,
                _library: library,
            })
        }
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), &'static str> {
        let (mut pk, mut sk) = (ptr::null_mut(), ptr::null_mut());
        let (mut pk_len, mut sk_len) = (0, 0);
        let rc = unsafe { (self.keygen)(&mut pk, &mut pk_len, &mut sk, &mut sk_len) };
        // The native API frees partial allocations on failure.
        if rc != 0 {
            return Err("key_generation_failed");
        }
        unsafe {
            let public = (!pk.is_null() && pk_len == PUBLIC_BYTES)
                .then(|| slice::from_raw_parts(pk, pk_len).to_vec());
            let secret = (!sk.is_null() && sk_len == SECRET_BYTES)
                .then(|| Zeroizing::new(slice::from_raw_parts(sk, sk_len).to_vec()));
            if !pk.is_null() {
                (self.free)(pk);
            }
            if !sk.is_null() {
                slice::from_raw_parts_mut(sk, sk_len).zeroize();
                (self.free)(sk);
            }
            public.zip(secret).ok_or("invalid_upstream_key_length")
        }
    }

    pub fn sign(&self, message: &[u8], secret: &[u8]) -> Result<Vec<u8>, &'static str> {
        if secret.len() != SECRET_BYTES {
            return Err("invalid_signing_key");
        }
        let mut sig = ptr::null_mut();
        let mut size = 0;
        let rc = unsafe {
            (self.sign)(
                message.as_ptr(),
                message.len(),
                secret.as_ptr(),
                &mut sig,
                &mut size,
            )
        };
        if rc != 0 || sig.is_null() {
            return Err("signing_failed");
        }
        unsafe {
            let value =
                (size == SIGNATURE_BYTES).then(|| slice::from_raw_parts(sig, size).to_vec());
            (self.free)(sig);
            value.ok_or("invalid_upstream_signature_length")
        }
    }

    pub fn verifies(&self, message: &[u8], signature: &[u8], public: &[u8]) -> bool {
        signature.len() == SIGNATURE_BYTES
            && public.len() == PUBLIC_BYTES
            && unsafe {
                (self.verify)(
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    public.as_ptr(),
                ) == 0
            }
    }
}

#[cfg(windows)]
fn open(path: &Path) -> Result<Library, libloading::Error> {
    use libloading::os::windows::{
        Library as WinLibrary, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    unsafe {
        WinLibrary::load_with_flags(
            path,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map(Into::into)
}

#[cfg(not(windows))]
fn open(path: &Path) -> Result<Library, libloading::Error> {
    unsafe { Library::new(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a deployed upstream shared library"]
    fn upstream_round_trip() {
        let path = env::var("CPQA_TEST_UPSTREAM_LIB").expect("set an absolute shared library path");
        let lib = Upstream::load_at(Path::new(&path)).unwrap();
        let (public, secret) = lib.generate_keypair().unwrap();
        let signature = lib.sign(b"native interoperability", &secret).unwrap();
        assert!(lib.verifies(b"native interoperability", &signature, &public));
        assert!(!lib.verifies(b"tampered", &signature, &public));
    }
}
