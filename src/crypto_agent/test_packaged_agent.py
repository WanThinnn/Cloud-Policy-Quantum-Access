"""Smoke-test the native messaging entry point in a generated installer."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from prepare_upstream import sha256


def call(exe, caller, message):
    data = json.dumps(message).encode("utf-8")
    result = subprocess.run([str(exe), caller], input=struct.pack("=I", len(data)) + data,
                            capture_output=True, check=True, timeout=20)
    assert result.stderr == b"", result.stderr
    size, = struct.unpack("=I", result.stdout[:4])
    assert size == len(result.stdout) - 4
    return json.loads(result.stdout[4:])


def main(folder):
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    entry, = manifest["packages"]
    artifact = folder / entry["filename"]
    assert sha256(artifact) == entry["sha256"]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with ZipFile(artifact) as archive:
            archive.extractall(root)
        name = "cpqa-crypto-agent.exe" if entry["target"].startswith("windows-") else "cpqa-crypto-agent"
        exe = root / "runtime" / name
        exe.chmod(0o700)
        config = json.loads(exe.with_name("crypto-agent.json").read_text(encoding="utf-8"))
        config_origin = config["origin"]
        caller = config["extensions"][0]
        operation = {"operation": "get_capabilities", "user_id": 1, "device_id": None}
        message = {"protocol": "cpqa-crypto/v1", "origin": config_origin, "command": operation}
        result = call(exe, caller, message)["result"]
        assert result["protocol"] == message["protocol"]
        assert result["version"] == entry["version"]
        assert {"enroll_signing_key", "sign_document"}.issubset(result["operations"])
        assert result["has_key"] is False
        if entry["target"].startswith("windows-"):
            # Exercise shutdown repeatedly because TKN20 starts Go runtime threads.
            for _ in range(20):
                assert call(exe, caller, message)["ok"] is True
        assert call(exe, caller + "unexpected", message)["code"] == "unauthorized_extension"
        assert call(exe, caller, {**message, "origin": config_origin + ".invalid"})["ok"] is False
        assert call(exe, caller, {**message, "command": {"operation": "sign_bytes"}})["ok"] is False
    print(f"Packaged agent passed native messaging smoke on {entry['target']}.")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
