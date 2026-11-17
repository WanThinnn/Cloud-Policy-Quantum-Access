"""Verify the packaged native messaging entry point and actual upstream ML-DSA."""

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
from uuid import uuid4
from urllib.parse import urlsplit
from zipfile import ZipFile

from prepare_upstream import LIBRARY, ROOT, sha256


def call(exe, caller, message):
    data = json.dumps(message).encode("utf-8")
    result = subprocess.run([str(exe), caller], input=struct.pack("=I", len(data)) + data,
                            capture_output=True, check=True, timeout=20)
    assert result.stderr == b"", result.stderr
    size, = struct.unpack("=I", result.stdout[:4])
    assert size == len(result.stdout) - 4
    return json.loads(result.stdout[4:])


def main(folder, expected_target=None):
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    entry, = manifest["packages"]
    if expected_target:
        assert entry["target"] == expected_target
    artifact = folder / entry["filename"]
    assert sha256(artifact) == entry["sha256"]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        system = entry["target"].split("-")[0]
        if system == "macos":
            assert entry["safari_bundled"] is True
            subprocess.run(["ditto", "-x", "-k", str(artifact), str(root)], check=True)
            app, = root.glob("*.app")
            subprocess.run(["codesign", "--verify", "--strict", "--deep", str(app)], check=True)
            contents = app / "Contents"
            exe = contents / "Helpers" / "cpqa-crypto-agent"
            config_path = contents / "Resources" / "crypto-agent.json"
            upstream = contents / "Frameworks" / f"{LIBRARY}.dylib"
            extension, = (contents / "PlugIns").glob("*.appex")
            check_safari(extension, upstream, entry["version"])
        else:
            with ZipFile(artifact) as archive:
                archive.extractall(root)
            name = "cpqa-crypto-agent.exe" if system == "windows" else "cpqa-crypto-agent"
            exe = root / "runtime" / name
            exe.chmod(0o700)
            config_path = exe.with_name("crypto-agent.json")
            suffix = {"windows": "dll", "linux": "so", "macos": "dylib"}[system]
            upstream = exe.with_name(f"{LIBRARY}.{suffix}")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert (root / entry["setup_script"]).is_file()
        assert (root / "SETUP.md").is_file()
        extension_manifest = json.loads((root / "extension" / "manifest.json").read_text(encoding="utf-8"))
        public_key = base64.b64decode(extension_manifest["key"], validate=True)
        prefix = hashlib.sha256(public_key).hexdigest()[:32]
        extension_id = prefix.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))
        assert f"chrome-extension://{extension_id}/" in config["extensions"]
        assert extension_id == entry["chromium_extension_id"]
        assert config["origin"] == entry["origin"]
        assert (root / "extension" / "background.js").is_file()
        assert (root / "extension" / "deployment.js").is_file()
        config_origin = config["origin"]
        caller = config["extensions"][0]
        operation = {"operation": "get_capabilities", "user_id": 1, "device_id": None}
        message = {"protocol": "cpqa-crypto/v1", "origin": config_origin, "command": operation}
        result = call(exe, caller, message)["result"]
        assert result["protocol"] == message["protocol"]
        assert result["version"] == entry["version"]
        assert {"enroll_signing_key", "sign_document"}.issubset(result["operations"])
        assert result["user_verification"] == "per_operation"
        assert result["has_key"] is False
        if system == "windows":
            # Exercise shutdown repeatedly because TKN20 starts Go runtime threads.
            for _ in range(20):
                assert call(exe, caller, message)["ok"] is True
        assert call(exe, caller + "unexpected", message)["code"] == "unauthorized_extension"
        assert call(exe, caller, {**message, "origin": config_origin + ".invalid"})["ok"] is False
        assert call(exe, caller, {**message, "command": {"operation": "sign_bytes"}})["ok"] is False
        subprocess.run(["cargo", "test", "--locked", "--manifest-path", str(ROOT / "Cargo.toml"),
                        "--lib", "upstream_round_trip", "--", "--ignored"],
                       check=True, env={**os.environ, "CPQA_TEST_UPSTREAM_LIB": str(upstream)})
    print(f"Package, extension identity, native messaging and upstream ML-DSA passed on {entry['target']}.")


def check_safari(extension, upstream, version):
    contents = extension / "Contents"
    config_path = contents / "Resources" / "crypto-agent.json"
    origin = json.loads(config_path.read_text(encoding="utf-8"))["origin"]
    manifest = json.loads((config_path.parent / "manifest.json").read_text(encoding="utf-8"))
    relay, = manifest["content_scripts"]
    assert relay["matches"] == [f"https://{urlsplit(origin).hostname}/*"]
    assert relay["all_frames"] is False
    assert "externally_connectable" not in manifest
    assert (config_path.parent / relay["js"][0]).read_text(encoding="utf-8").startswith(
        f"const cpqaSafariOrigin = {json.dumps(origin)};\n",
    )
    bridge = ctypes.CDLL(str(contents / "Frameworks" / "libcpqa_crypto_agent.dylib"))
    handle = bridge.cpqa_safari_handle_request
    handle.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
    handle.restype = ctypes.c_void_p
    release = bridge.cpqa_safari_free_response
    release.argtypes = [ctypes.c_void_p]
    release.restype = None

    def request(payload):
        frame = json.dumps(payload).encode("utf-8")
        result = handle(frame, len(frame), os.fsencode(config_path), os.fsencode(upstream))
        assert result
        try:
            return json.loads(ctypes.string_at(result))
        finally:
            release(result)

    message = {"protocol": "cpqa-crypto/v1", "origin": origin,
               "command": {"operation": "get_capabilities", "user_id": 1, "device_id": None}}
    capabilities = request(message)["result"]
    assert capabilities["version"] == version
    assert capabilities["verification_error"] == "os_verification_unsupported"
    assert request({**message, "origin": "https://wrong-origin.invalid"})["code"] == "unsupported_protocol_or_origin"
    assert request({**message, "command": {"operation": "sign_bytes"}})["code"] == "invalid_request"
    intent = json.dumps({
        "protocol": "cpqa-signing-intent/v2", "origin": origin, "operation": "enroll_signing_key",
        "request_id": str(uuid4()), "user_id": 1, "device_id": str(uuid4()), "expires_at": int(time.time()) + 60,
    })
    assert request({**message, "command": {"operation": "enroll_signing_key", "payload": intent}})["code"] == (
        "os_verification_unsupported"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]), *sys.argv[2:])
