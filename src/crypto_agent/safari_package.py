"""Build the local-use macOS app with Safari and Chromium entry points."""

from pathlib import Path
import plistlib
import shutil
import subprocess

from prepare_upstream import ROOT, TARGETS


APP_NAME = "CPQA Crypto Agent"
BUNDLE_ID = "com.cpqa.crypto-agent"


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def one_match(directory, pattern):
    matches = list(directory.glob(pattern))
    if len(matches) != 1:
        raise ValueError(f"Expected a single macOS build output matching {pattern}.")
    return matches[0]


def sign_locally(path, entitlements=None):
    command = ["codesign", "--force", "--sign", "-"]
    if entitlements:
        command.extend(["--entitlements", entitlements])
    run(*command, path)


def build_safari_app(work, bundle, javascript, target, config):
    tool = "safari-web-extension-packager"
    if subprocess.run(["xcrun", "--find", tool], capture_output=True).returncode:
        tool = "safari-web-extension-converter"
    project_root = work / "xcode"
    run("xcrun", tool, javascript, "--project-location", project_root, "--app-name", APP_NAME,
        "--bundle-identifier", BUNDLE_ID, "--macos-only", "--objc", "--copy-resources",
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
    if descriptor["NSExtension"]["NSExtensionPointIdentifier"] != "com.apple.Safari.web-extension":
        raise ValueError("The macOS app does not contain a Safari Web Extension.")
    installed_config = bundle / "runtime" / "crypto-agent.json"
    shutil.copy2(installed_config, extension_contents / "Resources" / installed_config.name)

    # Both Mac entry points use the same upstream binary and release provenance.
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

    # Use Apple's Sign to Run Locally equivalent and keep the extension sandbox.
    sandbox = work / "sandbox.plist"
    sandbox.write_bytes(plistlib.dumps({"com.apple.security.app-sandbox": True}))
    for item in (*libraries, bridge, executable):
        sign_locally(item)
    sign_locally(extension, sandbox)
    sign_locally(app, sandbox)
    run("codesign", "--verify", "--deep", "--strict", app)
    shutil.move(app, bundle / f"{APP_NAME}.app")
    # Preserve all upstream licenses and notices alongside the app.
    for name in (*TARGETS[target][1], "cpqa-crypto-agent", "crypto-agent.json"):
        (upstream / name).unlink()
    (bundle / "native-host.json").unlink()
