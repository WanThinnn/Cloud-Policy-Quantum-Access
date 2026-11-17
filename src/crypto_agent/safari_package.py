"""Build the signed macOS app that contains Safari and Chromium entry points."""

import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

from prepare_upstream import ROOT, TARGETS


APP_NAME = "CPQA Crypto Agent"
BUNDLE_ID = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
TEAM_ID = re.compile(r"[A-Z0-9]{10}")


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def one_match(directory, pattern):
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        raise ValueError(f"Expected a single macOS build output matching {pattern}.")
    return matches[0]


def code_signer(identity, team):
    keychain = os.environ.get("CPQA_CODESIGN_KEYCHAIN")

    def sign(path, entitlements=None):
        command = ["codesign", "--force", "--sign", identity, "--timestamp", "--options", "runtime"]
        if keychain:
            command.extend(["--keychain", keychain])
        if entitlements:
            command.extend(["--entitlements", entitlements])
        run(*command, path)
        display = run("codesign", "-dv", "--verbose=4", path, capture_output=True, text=True).stderr
        if (f"TeamIdentifier={team}" not in display.splitlines()
                or not any(line.startswith("Authority=Developer ID Application: ") for line in display.splitlines())):
            raise ValueError("The macOS signature does not belong to the requested Developer ID team.")

    return sign


def build_safari_app(work, bundle, javascript, target, config, args):
    tool = "safari-web-extension-packager"
    if subprocess.run(["xcrun", "--find", tool], capture_output=True).returncode:
        tool = "safari-web-extension-converter"
    project_root = work / "xcode"
    run("xcrun", tool, javascript, "--project-location", project_root, "--app-name", APP_NAME,
        "--bundle-identifier", args.safari_bundle_id, "--macos-only", "--objc", "--copy-resources",
        "--no-open", "--no-prompt")
    project = one_match(project_root, "**/*.xcodeproj")
    handler = one_match(project_root, "**/SafariWebExtensionHandler.m")
    shutil.copyfile(ROOT / "safari" / handler.name, handler)
    products = work / "products"
    version = config["version"]
    major, minor, patch = map(int, version.split("."))
    run("xcodebuild", "-project", project, "-alltargets", "-configuration", "Release", "-sdk", "macosx",
        f"CONFIGURATION_BUILD_DIR={products}", f"ARCHS={target[1]}", "ONLY_ACTIVE_ARCH=YES",
        "MACOSX_DEPLOYMENT_TARGET=13.0", f"MARKETING_VERSION={version}",
        f"CURRENT_PROJECT_VERSION={major + 1}.{minor}.{patch}",
        "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO")
    app = one_match(products, "*.app")
    app_contents = app / "Contents"
    extension = one_match(app_contents / "PlugIns", "*.appex")
    extension_contents = extension / "Contents"
    descriptor = plistlib.loads((extension_contents / "Info.plist").read_bytes())
    extension_id = descriptor["CFBundleIdentifier"]
    if not extension_id.startswith(f"{args.safari_bundle_id}.") or not BUNDLE_ID.fullmatch(extension_id):
        raise ValueError("Unexpected Safari extension bundle identifier.")
    installed_config = bundle / "runtime" / "crypto-agent.json"
    shutil.copy2(installed_config, extension_contents / "Resources" / installed_config.name)

    # Both signed Mac entry points use the same upstream binary. Keep the release
    # provenance with it before applying Apple's required distribution signature.
    upstream = bundle / "runtime"
    app_frameworks = app_contents / "Frameworks"
    app_frameworks.mkdir(exist_ok=True)
    libraries = [shutil.copy2(upstream / name, app_frameworks) for name in TARGETS[target][1]]
    resources = app_contents / "Resources"
    shutil.copy2(installed_config, resources)
    shutil.copy2(bundle / "native-host.json", resources)
    shutil.copy2(upstream / "upstream-manifest.json", resources)

    helpers = app_contents / "Helpers"
    helpers.mkdir(exist_ok=True)
    executable = Path(shutil.copy2(upstream / "cpqa-crypto-agent", helpers))
    run("cargo", "rustc", "--locked", "--release", "--lib", "--crate-type", "cdylib",
        "--manifest-path", ROOT / "Cargo.toml", "--target-dir", ROOT / "target")
    extension_frameworks = extension_contents / "Frameworks"
    extension_frameworks.mkdir(exist_ok=True)
    bridge = Path(shutil.copy2(ROOT / "target" / "release" / "libcpqa_crypto_agent.dylib", extension_frameworks))
    for item in (*libraries, bridge, executable):
        run("lipo", "-verify_arch", target[1], item)

    # Keep the Safari extension sandbox while allowing the shared Rust code to
    # load the signed, same-team libraries. No Hardened Runtime exceptions.
    sandbox = work / "sandbox.plist"
    sandbox.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}))
    sign = code_signer(args.macos_signing_identity, args.apple_team_id)
    for item in (*libraries, bridge, executable):
        sign(item)
    sign(extension, sandbox)
    sign(app, sandbox)
    run("codesign", "--verify", "--deep", "--strict", app)

    archive = work / "macos-notarization.zip"
    run("ditto", "-c", "-k", "--keepParent", app, archive)
    submit = ["xcrun", "notarytool", "submit", archive, "--keychain-profile", args.notary_profile,
              "--wait", "--output-format", "json"]
    if keychain := os.environ.get("CPQA_CODESIGN_KEYCHAIN"):
        submit.extend(["--keychain", keychain])
    result = run(*submit, capture_output=True, text=True)
    decision = json.loads(result.stdout)
    if decision.get("status") != "Accepted":
        raise ValueError(f"Apple did not accept the macOS notarization (submission {decision.get('id')}).")
    run("xcrun", "stapler", "staple", app)
    run("xcrun", "stapler", "validate", app)
    run("codesign", "--verify", "--deep", "--strict", app)
    shutil.move(app, bundle / f"{APP_NAME}.app")
    # Preserve all upstream licenses and notices alongside the app.
    for name in (*TARGETS[target][1], "cpqa-crypto-agent", "crypto-agent.json"):
        (upstream / name).unlink()
    (bundle / "native-host.json").unlink()
    return f"{extension_id} ({args.apple_team_id})"
