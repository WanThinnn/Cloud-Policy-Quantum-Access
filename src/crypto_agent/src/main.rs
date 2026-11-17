#![cfg_attr(windows, windows_subsystem = "windows")]

mod store;

use base64::{engine::general_purpose::STANDARD, Engine};
use cpqa_crypto_agent::upstream::Upstream;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const PROTOCOL: &str = "cpqa-crypto/v1";
const MAX_MESSAGE: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    origin: String,
    extensions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    origin: String,
    command: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    GetCapabilities {
        user_id: u64,
        device_id: Option<Uuid>,
    },
    EnrollSigningKey {
        payload: String,
    },
    SignDocument {
        payload: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    protocol: String,
    origin: String,
    operation: String,
    request_id: Uuid,
    user_id: u64,
    device_id: Uuid,
    expires_at: u64,
    key_id: Option<u64>,
    file_id: Option<u64>,
    version: Option<u64>,
    target: Option<String>,
    sha3_256: Option<String>,
}

fn is_digest(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn validate_intent(
    payload: &str,
    origin: &str,
    operation: &str,
    now: u64,
) -> Result<Intent, &'static str> {
    if !payload.is_ascii() || payload.len() > 4096 {
        return Err("invalid_intent");
    }
    let intent: Intent = serde_json::from_str(payload).map_err(|_| "invalid_intent")?;
    if intent.protocol != PROTOCOL
        || intent.origin != origin
        || intent.operation != operation
        || intent.request_id.is_nil()
        || intent.device_id.is_nil()
        || intent.user_id == 0
        || intent.expires_at <= now
        || intent.expires_at - now > 185
    {
        return Err("invalid_intent");
    }
    let valid = if operation == "sign_document" {
        intent.key_id.is_some_and(|id| id > 0)
            && intent.version.is_some_and(|version| version > 0)
            && intent.file_id != Some(0)
            && is_digest(intent.target.as_deref())
            && is_digest(intent.sha3_256.as_deref())
    } else {
        intent.key_id.is_none()
            && intent.file_id.is_none()
            && intent.version.is_none()
            && intent.target.is_none()
            && intent.sha3_256.is_none()
    };
    valid.then_some(intent).ok_or("invalid_intent")
}

fn handle(config: &Config, request: Request) -> Result<Value, &'static str> {
    if request.protocol != PROTOCOL || config.origin != request.origin {
        return Err("unsupported_protocol_or_origin");
    }
    let origin = &config.origin;
    let lib = Upstream::load()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid_clock")?
        .as_secs();
    match request.command {
        Operation::GetCapabilities { user_id, device_id } => {
            let has_key = if let Some(device_id) = device_id {
                let location = store::SigningKey::new(origin, user_id, device_id)?;
                if location.exists()? {
                    location.open()?;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            Ok(json!({
                "protocol": PROTOCOL,
                "version": env!("CARGO_PKG_VERSION"),
                "operations": ["get_capabilities", "enroll_signing_key", "sign_document"],
                "has_key": has_key
            }))
        }
        Operation::EnrollSigningKey { payload } => {
            let intent = validate_intent(&payload, origin, "enroll_signing_key", now)?;
            let location = store::SigningKey::new(origin, intent.user_id, intent.device_id)?;
            let (public, secret) = lib.generate_keypair()?;
            let public = STANDARD.encode(public);
            let proof = lib.sign(format!("{payload}\n{public}").as_bytes(), &secret)?;
            location.save(&secret)?;
            Ok(json!({"public_key": public, "signature": STANDARD.encode(proof)}))
        }
        Operation::SignDocument { payload } => {
            let intent = validate_intent(&payload, origin, "sign_document", now)?;
            let location = store::SigningKey::new(origin, intent.user_id, intent.device_id)?;
            let signature = lib.sign(payload.as_bytes(), &location.open()?)?;
            Ok(json!({"signature": STANDARD.encode(signature)}))
        }
    }
}

fn read_request(input: &mut impl Read) -> Result<Request, &'static str> {
    let mut length = [0; 4];
    input.read_exact(&mut length).map_err(|_| "invalid_frame")?;
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err("invalid_frame");
    }
    let mut frame = vec![0; length];
    input.read_exact(&mut frame).map_err(|_| "invalid_frame")?;
    serde_json::from_slice(&frame).map_err(|_| "invalid_request")
}

fn run() -> Result<Value, &'static str> {
    let exe = env::current_exe().map_err(|_| "invalid_installation")?;
    let config =
        fs::read(exe.with_file_name("crypto-agent.json")).map_err(|_| "invalid_installation")?;
    let config: Config = serde_json::from_slice(&config).map_err(|_| "invalid_installation")?;
    let caller = env::args().nth(1).ok_or("unauthorized_extension")?;
    if !config.extensions.contains(&caller) {
        return Err("unauthorized_extension");
    }
    handle(&config, read_request(&mut io::stdin().lock())?)
}

fn main() -> io::Result<()> {
    let body = match run() {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(code) => json!({"ok": false, "code": code}),
    };
    let body = serde_json::to_vec(&body)?;
    let mut out = io::stdout().lock();
    out.write_all(&(body.len() as u32).to_ne_bytes())?;
    out.write_all(&body)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_capabilities_and_rejects_unknown_operations_and_oversize() {
        let valid = br#"{"protocol":"cpqa-crypto/v1","origin":"https://cpqa.example","command":{"operation":"get_capabilities","user_id":1,"device_id":null}}"#;
        let mut frame = (valid.len() as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(valid);
        assert!(read_request(&mut frame.as_slice()).is_ok());
        assert!(read_request(&mut ((MAX_MESSAGE + 1) as u32).to_ne_bytes().as_slice()).is_err());
        let invalid = br#"{"protocol":"cpqa-crypto/v1","origin":"https://cpqa.example","command":{"operation":"sign_bytes","payload":"abc"}}"#;
        assert!(serde_json::from_slice::<Request>(invalid).is_err());
        let extra = br#"{"protocol":"cpqa-crypto/v1","origin":"https://cpqa.example","command":{"operation":"get_capabilities","user_id":1,"unexpected":true}}"#;
        assert!(serde_json::from_slice::<Request>(extra).is_err());
    }
}
