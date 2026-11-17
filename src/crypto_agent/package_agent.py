"""Bundle a built Crypto Agent and produce its deployment catalog entry."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

from prepare_upstream import ROOT, TARGETS, native_target, sha256
from safari_package import build_safari_app


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def extension_files(directory, config, hostname, public_key=None, safari=False):
    directory.mkdir()
    manifest = {
        "manifest_version": 3, "name": "CPQA Crypto Agent", "version": config["version"],
        "permissions": ["nativeMessaging"],
        "background": {"service_worker": "background.js", "type": "module"},
    }
    pattern = f"https://{hostname}/*"
    if safari:
        manifest["content_scripts"] = [{
            "matches": [pattern], "js": ["safari-content.js"], "run_at": "document_start", "all_frames": False,
        }]
        content = (ROOT / "extension" / "safari-content.js").read_text(encoding="utf-8")
        (directory / "safari-content.js").write_text(
            f"const cpqaSafariOrigin = {json.dumps(config['origin'])};\n{content}", encoding="utf-8",
        )
    else:
        manifest["externally_connectable"] = {"matches": [pattern]}
    if public_key:
        manifest["key"] = public_key
    write_json(directory / "manifest.json", manifest)
    (directory / "deployment.js").write_text(
        f"export const origin = {json.dumps(config['origin'])};\n"
        f"export const safari = {json.dumps(safari)};\n",
        encoding="utf-8",
    )
    shutil.copyfile(ROOT / "extension" / "background.js", directory / "background.js")


def package(root, runtime, exe, config, target, output, hostname, args):
    manifest = json.loads((runtime / "upstream-manifest.json").read_text(encoding="utf-8"))
    system, arch = target
    if (manifest["platform"], manifest["arch"]) != target:
        raise ValueError("The upstream bundle does not match this build target.")
    for library in TARGETS[target][1]:
        if sha256(runtime / library) != manifest["libraries"].get(library):
            raise ValueError(f"Upstream library failed verification: {library}.")
    bundle = root / "package"
    shutil.copytree(runtime, bundle / "runtime")
    shutil.copy2(exe, bundle / "runtime")
    windows = system == "windows"
    installer = "setup.ps1" if windows else "setup.sh"
    shutil.copy2(ROOT / "install" / installer, bundle / installer)
    shutil.copy2(ROOT / "install" / "SETUP.md", bundle / "SETUP.md")
    extension_files(bundle / "extension", config, hostname, args.extension_key)
    write_json(bundle / "runtime" / "crypto-agent.json", {
        "origin": config["origin"], "extensions": config["extension_origins"],
    })
    write_json(bundle / "native-host.json", {
        "name": "com.cpqa.crypto_agent", "description": "CPQA Crypto Agent",
        "path": "__CPQA_EXECUTABLE__", "type": "stdio", "allowed_origins": config["extension_origins"],
    })
    target_id = f"{system}-{arch}"
    name = f"cpqa-crypto-agent-{target_id}-{config['version']}.zip"
    artifact = output / name
    entry = {
        "target": target_id, "version": config["version"], "filename": name, "setup_script": installer,
        "origin": config["origin"], "chromium_extension_id": args.extension_id[0],
    }
    if system == "macos":
        javascript = root / "safari"
        extension_files(javascript, config, hostname, safari=True)
        build_safari_app(root, bundle, javascript, target, config)
        entry["safari_bundled"] = True
        # Preserve bundle metadata and executable modes through ZIP extraction.
        subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", str(bundle), str(artifact)], check=True)
    else:
        with ZipFile(artifact, "x", ZIP_DEFLATED) as archive:
            for item in sorted(bundle.rglob("*")):
                if item.is_file():
                    archive.write(item, item.relative_to(bundle))
    entry["sha256"] = sha256(artifact)
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--extension-id", action="append", help="Override the derived Chromium extension ID.")
    parser.add_argument("--extension-key", help="Override the bundled Chromium extension public key (Base64 DER).")
    parser.add_argument("--source", choices=("release", "source"), default="release")
    parser.add_argument("--ref", help="Upstream Git ref or release tag.")
    parser.add_argument("--runtime-dir", type=Path, help="Use an existing prepare_upstream.py bundle.")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        origin = urlsplit(args.origin)
        if (origin.scheme != "https" or not origin.hostname or origin.netloc != args.origin[8:]
                or not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", origin.netloc)
                or origin.port == 443):
            raise ValueError("--origin must be a canonical HTTPS origin, such as https://cpqa.example.")
        if args.extension_key is None:
            args.extension_key = (ROOT / "extension" / "chromium-public-key.b64").read_text(encoding="ascii").strip()
        key = base64.b64decode(args.extension_key, validate=True)
        if not key:
            raise ValueError("Supply the Chromium extension's DER public key.")
        prefix = hashlib.sha256(key).hexdigest()[:32]
        extension_id = prefix.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))
        if args.extension_id is None:
            args.extension_id = [extension_id]
        if any(not re.fullmatch(r"[a-p]{32}", value) for value in args.extension_id):
            raise ValueError("Supply valid Chrome or Edge extension IDs.")
        if extension_id != args.extension_id[0]:
            raise ValueError("The extension public key does not match the first (Chromium) extension ID.")
        target = native_target()
        config = {
            "origin": args.origin,
            "extension_origins": [f"chrome-extension://{value}/" for value in dict.fromkeys(args.extension_id)],
            "version": re.search(r'^version = "(\d+\.\d+\.\d+)"$', (ROOT / "Cargo.toml").read_text(),re.MULTILINE)[1],}
        output = args.output_dir.absolute()
        if output.exists():
            raise FileExistsError(f"Choose a new output directory: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".cpqa-package-", dir=output.parent) as directory:
            root = Path(directory)
            staging = root / "artifacts"
            staging.mkdir()
            runtime = args.runtime_dir.resolve() if args.runtime_dir else root / "upstream"
            if not args.runtime_dir:
                command = [sys.executable, str(ROOT / "prepare_upstream.py"), "--source", args.source,
                           "--output-dir", str(runtime)]
                if args.ref:
                    command.extend(["--ref", args.ref])
                subprocess.run(command, check=True)
            target_dir = ROOT / "target"
            subprocess.run(["cargo", "build", "--locked", "--release", "--manifest-path", str(ROOT / "Cargo.toml"),
                            "--target-dir", str(target_dir)], check=True)
            exe = target_dir / "release" / ("cpqa-crypto-agent.exe" if target[0] == "windows" else "cpqa-crypto-agent")
            entry = package(root, runtime, exe, config, target, staging, origin.hostname, args)
            write_json(staging / "manifest.json", {"revision": 1, "packages": [entry]})
            staging.rename(output)
        print(output)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Packaging failed: {error}\n")


if __name__ == "__main__":
    main()
