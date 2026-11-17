use crate::upstream::SECRET_BYTES;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm,
};
use keyring::Entry;
use std::{fs, io::Write, path::PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

const SERVICE: &str = "CPQA Crypto Agent Signing Keys";
const STORE_ERROR: &str = "local_key_store_unavailable";
const NONCE_SIZE: usize = 12;
const ENVELOPE_SIZE: usize = 1 + NONCE_SIZE + SECRET_BYTES + 16;

pub struct SigningKey {
    label: String,
    path: PathBuf,
}

impl SigningKey {
    pub fn new(origin: &str, user: u64, device: Uuid) -> Result<Self, &'static str> {
        if user == 0 || device.is_nil() {
            return Err("invalid_device");
        }
        let path = dirs::data_local_dir()
            .ok_or(STORE_ERROR)?
            .join("cpqa")
            .join("crypto-agent")
            .join("signing")
            .join(format!("{device}.bin"));
        Ok(Self {
            label: format!("{origin}|{user}|{device}"),
            path,
        })
    }

    pub fn exists(&self) -> Result<bool, &'static str> {
        self.path.try_exists().map_err(|_| STORE_ERROR)
    }

    fn entry(&self) -> Result<Entry, &'static str> {
        Entry::new(SERVICE, &self.label).map_err(|_| STORE_ERROR)
    }

    fn aad(&self) -> Vec<u8> {
        format!("cpqa/signing-key/v1|{}", self.label).into_bytes()
    }

    pub fn save(&self, secret: &[u8]) -> Result<(), &'static str> {
        let parent = self.path.parent().ok_or(STORE_ERROR)?;
        fs::create_dir_all(parent).map_err(|_| STORE_ERROR)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&self.path).map_err(|_| STORE_ERROR)?;
        let result = self.write_key(secret, &mut output);
        drop(output);
        if result.is_err() {
            let _ = fs::remove_file(&self.path);
        }
        result
    }

    fn write_key(&self, secret: &[u8], output: &mut fs::File) -> Result<(), &'static str> {
        let entry = self.entry()?;
        let mut key = Zeroizing::new([0; 32]);
        let mut nonce = [0; NONCE_SIZE];
        OsRng
            .try_fill_bytes(key.as_mut())
            .map_err(|_| STORE_ERROR)?;
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| STORE_ERROR)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| STORE_ERROR)?;
        let blob = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: secret,
                    aad: &self.aad(),
                },
            )
            .map_err(|_| STORE_ERROR)?;
        output.write_all(&[1]).map_err(|_| STORE_ERROR)?;
        output.write_all(&nonce).map_err(|_| STORE_ERROR)?;
        output.write_all(&blob).map_err(|_| STORE_ERROR)?;
        output.sync_all().map_err(|_| STORE_ERROR)?;
        entry.set_secret(key.as_ref()).map_err(|_| STORE_ERROR)
    }

    pub fn open(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        use std::io::Read;

        let mut envelope = Vec::with_capacity(ENVELOPE_SIZE + 1);
        fs::File::open(&self.path)
            .map_err(|_| STORE_ERROR)?
            .take((ENVELOPE_SIZE + 1) as u64)
            .read_to_end(&mut envelope)
            .map_err(|_| STORE_ERROR)?;
        if envelope.len() != ENVELOPE_SIZE || envelope[0] != 1 {
            return Err(STORE_ERROR);
        }
        let key = Zeroizing::new(self.entry()?.get_secret().map_err(|_| STORE_ERROR)?);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| STORE_ERROR)?;
        let nonce: &[u8; NONCE_SIZE] = envelope[1..1 + NONCE_SIZE]
            .try_into()
            .map_err(|_| STORE_ERROR)?;
        let secret = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: &envelope[1 + NONCE_SIZE..],
                    aad: &self.aad(),
                },
            )
            .map_err(|_| STORE_ERROR)?;
        Ok(Zeroizing::new(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires access to the current OS credential store"]
    fn credential_store_round_trip_and_aad_binding() {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let id = Uuid::from_bytes(random);
        let key = SigningKey {
            label: format!("cpqa-test-{id}"),
            path: std::env::temp_dir().join(format!("cpqa-test-{id}.bin")),
        };
        let value = Zeroizing::new(vec![13u8; SECRET_BYTES]);
        let saved = key.save(&value);
        let opened = key.open();
        let wrong_identity = SigningKey {
            label: format!("cpqa-other-{id}"),
            path: key.path.clone(),
        };
        let entry = wrong_identity.entry().unwrap();
        let wrapping_key = Zeroizing::new(key.entry().unwrap().get_secret().unwrap_or_default());
        let copied = entry.set_secret(&wrapping_key);
        let rejected = wrong_identity.open().is_err();
        let _ = entry.delete_credential();
        let _ = key.entry().unwrap().delete_credential();
        let _ = fs::remove_file(&key.path);
        saved.unwrap();
        assert_eq!(*opened.unwrap(), *value);
        copied.unwrap();
        assert!(rejected);
    }
}
