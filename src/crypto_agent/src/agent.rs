use crate::{consent, store, upstream::Upstream};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const PROTOCOL: &str = "cpqa-crypto/v1";
const INTENT_PROTOCOL: &str = "cpqa-signing-intent/v2";
pub const MAX_MESSAGE: usize = 16_384;

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
    if intent.protocol != INTENT_PROTOCOL
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

fn unix_time() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "invalid_clock")
}

fn confirm_intent(intent: &Intent, message: &str) -> Result<(), &'static str> {
    consent::confirm(message)?;
    if unix_time()? >= intent.expires_at {
        return Err("signing_intent_expired");
    }
    Ok(())
}

fn handle(
    config: &Config,
    request: Request,
    load_upstream: impl FnOnce() -> Result<&'static Upstream, &'static str>,
) -> Result<Value, &'static str> {
    if request.protocol != PROTOCOL || config.origin != request.origin {
        return Err("unsupported_protocol_or_origin");
    }
    let origin = &config.origin;
    let lib = load_upstream()?;
    let now = unix_time()?;
    match request.command {
        Operation::GetCapabilities { user_id, device_id } => {
            let has_key = if let Some(device_id) = device_id {
                store::SigningKey::new(origin, user_id, device_id)?.exists()?
            } else {
                false
            };
            Ok(json!({
                "protocol": PROTOCOL,
                "version": env!("CARGO_PKG_VERSION"),
                "operations": ["get_capabilities", "enroll_signing_key", "sign_document"],
                "has_key": has_key,
                "user_verification": "per_operation",
                "verification_error": consent::check_availability().err()
            }))
        }
        Operation::EnrollSigningKey { payload } => {
            let intent = validate_intent(&payload, origin, "enroll_signing_key", now)?;
            confirm_intent(
                &intent,
                "CPQA wants to register this device for document signing.",
            )?;
            let location = store::SigningKey::new(origin, intent.user_id, intent.device_id)?;
            let (public, secret) = lib.generate_keypair()?;
            let public = STANDARD.encode(public);
            let proof = lib.sign(format!("{payload}\n{public}").as_bytes(), &secret)?;
            location.save(&secret)?;
            Ok(json!({"public_key": public, "signature": STANDARD.encode(proof)}))
        }
        Operation::SignDocument { payload } => {
            let intent = validate_intent(&payload, origin, "sign_document", now)?;
            confirm_intent(
                &intent,
                "CPQA wants to sign the selected document for upload.",
            )?;
            let location = store::SigningKey::new(origin, intent.user_id, intent.device_id)?;
            let signature = lib.sign(payload.as_bytes(), &location.open()?)?;
            Ok(json!({"signature": STANDARD.encode(signature)}))
        }
    }
}

impl Config {
    fn read(path: &Path) -> Result<Self, &'static str> {
        let config = fs::read(path).map_err(|_| "invalid_installation")?;
        serde_json::from_slice(&config).map_err(|_| "invalid_installation")
    }
}

pub fn handle_chromium(
    executable: &Path,
    caller: &str,
    read_message: impl FnOnce() -> Result<Vec<u8>, &'static str>,
) -> Result<Value, &'static str> {
    #[cfg(target_os = "macos")]
    let config_path =
        mac_app_contents(executable).map(|contents| contents.join("Resources/crypto-agent.json"));
    #[cfg(not(target_os = "macos"))]
    let config_path = None;
    let config = Config::read(
        &config_path.unwrap_or_else(|| executable.with_file_name("crypto-agent.json")),
    )?;
    if !config
        .extensions
        .iter()
        .any(|extension| extension == caller)
    {
        return Err("unauthorized_extension");
    }
    dispatch(&config, &read_message()?, Upstream::load)
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_app_contents(executable: &Path) -> Option<&Path> {
    let helpers = executable.parent()?;
    if helpers.file_name()? != "Helpers" {
        return None;
    }
    helpers.parent().filter(|path| path.ends_with("Contents"))
}

fn dispatch(
    config: &Config,
    frame: &[u8],
    load_upstream: impl FnOnce() -> Result<&'static Upstream, &'static str>,
) -> Result<Value, &'static str> {
    if frame.is_empty() || frame.len() > MAX_MESSAGE {
        return Err("invalid_frame");
    }
    let request = serde_json::from_slice(frame).map_err(|_| "invalid_request")?;
    handle(config, request, load_upstream)
}

pub fn response(result: Result<Value, &'static str>) -> Value {
    match result {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(code) => json!({"ok": false, "code": code}),
    }
}

#[cfg(target_os = "macos")]
mod safari;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_invalid_request_before_loading_the_upstream() {
        let origin = "https://cpqa.example";
        let config = Config {
            origin: origin.to_owned(),
            extensions: Vec::new(),
        };
        let command = json!({"operation": "get_capabilities", "user_id": 1, "device_id": null});
        let request = |origin: &str, command: Value| {
            serde_json::to_vec(&json!({"protocol": PROTOCOL, "origin": origin, "command": command}))
                .unwrap()
        };
        let reject_load = || panic!("rejected requests must not load the native library");
        assert_eq!(
            dispatch(
                &config,
                &request("https://foreign.example", command.clone()),
                reject_load
            ),
            Err("unsupported_protocol_or_origin")
        );
        assert_eq!(
            dispatch(
                &config,
                &request(origin, json!({"operation": "sign_bytes", "payload": "abc"})),
                reject_load
            ),
            Err("invalid_request")
        );
        let mut extra = command;
        extra["unexpected"] = json!(true);
        assert_eq!(
            dispatch(&config, &request(origin, extra), reject_load),
            Err("invalid_request")
        );
    }
}
