#![cfg_attr(windows, windows_subsystem = "windows")]

use cpqa_crypto_agent::agent::{handle_chromium, response, MAX_MESSAGE};
use serde_json::Value;
use std::{
    env,
    io::{self, Read, Write},
};

fn read_request(input: &mut impl Read) -> Result<Vec<u8>, &'static str> {
    let mut length = [0; 4];
    input.read_exact(&mut length).map_err(|_| "invalid_frame")?;
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err("invalid_frame");
    }
    let mut frame = vec![0; length];
    input.read_exact(&mut frame).map_err(|_| "invalid_frame")?;
    Ok(frame)
}

fn run() -> Result<Value, &'static str> {
    let exe = env::current_exe().map_err(|_| "invalid_installation")?;
    let caller = env::args().nth(1).ok_or("unauthorized_extension")?;
    handle_chromium(&exe, &caller, || read_request(&mut io::stdin().lock()))
}

fn main() -> io::Result<()> {
    let body = serde_json::to_vec(&response(run()))?;
    let mut out = io::stdout().lock();
    out.write_all(&(body.len() as u32).to_ne_bytes())?;
    out.write_all(&body)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_bounded_native_message() {
        let valid = br#"{"protocol":"cpqa-crypto/v1","origin":"https://cpqa.example","command":{"operation":"get_capabilities","user_id":1,"device_id":null}}"#;
        let mut frame = (valid.len() as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(valid);
        assert!(read_request(&mut frame.as_slice()).is_ok());
        assert!(read_request(&mut ((MAX_MESSAGE + 1) as u32).to_ne_bytes().as_slice()).is_err());
    }
}
