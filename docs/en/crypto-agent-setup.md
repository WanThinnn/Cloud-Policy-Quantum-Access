# Set up Crypto Agent

Open **Manage Security Keys**, then select **Check Crypto Agent**. Follow the
action shown for the browser or the device. The download list includes only
installers published by your administrator. If CPQA suggests a package, verify
the architecture before downloading it.
If the check button is disabled, an administrator must enable Crypto Agent for this deployment.

1. Sign in to CPQA and open **Security Keys → Download Crypto Agent**.
   Download the ZIP for your operating system, verify the displayed SHA-256,
   and extract it. The ZIP includes Crypto Agent, its browser extension and
   `SETUP.md`.
2. Run setup once from the extracted directory as the same user who runs the
   browser. On Windows run `powershell -NoProfile -File .\setup.ps1`. On
   macOS or Linux run `bash ./setup.sh`. Setup chooses the local paths.
3. Enable the extension using the browser instructions below.
4. Return to CPQA and select **Check Crypto Agent**. When enrollment is
   available, select **Register signing device**. Each browser profile uses
   its own local registration reference.

### Enable the Chromium extension

1. Open the Extensions page for your browser. Chrome and Chromium use
   `chrome://extensions`, Edge uses `edge://extensions`, Brave uses
   `brave://extensions`, and Vivaldi uses `vivaldi://extensions`.
2. Enable **Developer mode**, choose **Load unpacked**, and select the local
   `extension` directory printed by setup. Reload CPQA. That directory remains
   in place when you remove the extracted ZIP files.

Setups register the native host for standard browser profile paths. Custom
Chromium builds and managed browsers may require administrator configuration
for Native Messaging or unpacked extensions. Follow the device's script and
browser policies.

### Enable the Safari extension on macOS

For a package built with Safari support, setup copies the app into
`~/Applications`. In **Safari → Settings →
Extensions**, enable **CPQA Crypto Agent**, grant it access to the CPQA
site, and reload the page.

The macOS and Linux packages support the connection check. Enrollment and
signing require platform key protection and user verification and currently
return a verification error on these platforms.

## Publish installers

Run the manual **Build Crypto Agent installers** workflow with the CPQA HTTPS
origin, the Chromium extension ID, and its matching Base64 DER **public** key.
The workflow produces an all-in-one installer ZIP and a catalog entry for each
platform. The public key gives the bundled Chromium extension the same ID in
all local installation folders. An optional Edge Add-ons ID can also be
allowed for previously published extensions.

The default build includes Chromium ZIPs for Windows, Linux, Mac Intel and
Apple silicon. It requires no Apple Developer account.

Pass `safari_bundle_id` to include Safari in the notarized macOS app. These
jobs use the `crypto-agent-macos` GitHub environment. Set the `APPLE_TEAM_ID`
variable and the following secrets there. Limit that environment to branches
or tags you trust to build and sign.

| Secret | Value |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12_BASE64` | Base64-encoded Developer ID Application PKCS#12 with the signing key |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | Password for the PKCS#12 file |
| `APPLE_NOTARY_KEY_P8_BASE64` | Base64-encoded App Store Connect team API key file for notarization |
| `APPLE_NOTARY_KEY_ID` | ID of the notarization API key |
| `APPLE_NOTARY_ISSUER_ID` | Issuer ID of the notarization API key |

After the workflow changes are on GitHub, dispatch it from the local CLI.
Set the shell variables for the deployment origin, Chromium extension ID, and
extension public key. To include Safari, add
`-f "safari_bundle_id=$macBundleId"`.

```powershell
rtk gh workflow run crypto-agent.yml --ref $releaseBranch -f "origin=$cpqaOrigin" -f "chrome_id=$chromeExtensionId" -f "extension_key=$chromeExtensionPublicKey"
rtk gh run list --workflow crypto-agent.yml
rtk gh run watch $runId --exit-status
rtk gh run download $runId --pattern 'crypto-agent-*' --dir agent-artifacts
```

Omit `upstream_tag` to use the current upstream release, or pass
`-f upstream_tag=v6.0.0` to use that
tag on all runners. For a local upstream source build, use `package_agent.py`
with `--source source --ref` and the upstream build dependencies.

For a local Windows pilot, run in an x64 Visual Studio developer shell with
Python and Rust available. Use your deployed extension ID in the command.

```powershell
rtk python src/crypto_agent/package_agent.py --origin $cpqaOrigin --extension-id $chromeExtensionId --extension-key $chromeExtensionPublicKey --ref v6.0.0 --output-dir src/crypto_agent/target/distribution
```

For a single platform, copy the installer and its `manifest.json` to
`config/crypto-agent/` on the CPQA server. For multiple platforms, assemble a
single manifest with `revision: 1` and one `packages` entry per platform.
Publish versioned packages first and replace the catalog after the files are in
place. The default Compose configuration makes that directory visible to Django
as `/config/crypto-agent`. Keep it writable only by the release operator.

In the deployment environment set `CRYPTO_AGENT_ORIGIN` to the exact origin used
for packaging. CPQA reads browser extension IDs from the published catalog.
Existing `CRYPTO_AGENT_CHROME_EXTENSION_ID` and
`CRYPTO_AGENT_SAFARI_EXTENSION_ID` settings take precedence when set. If you
publish a separate Edge Add-ons extension, set `CRYPTO_AGENT_EDGE_EXTENSION_ID`.
Keep a single Chromium extension ID across packages in the catalog. Set
`CRYPTO_AGENT_MIN_VERSION` to the minimum
compatible agent version. Apply the Django migrations, recreate the web
container with `NATIVE_SIGNING_ENABLED=true`, and verify setup with a pilot user.
Keep `NATIVE_SIGNING_REQUIRED=false` until the distribution and onboarding
paths have been verified for users.

### First Edge setup on a Windows pilot device

1. Run `setup.ps1` from the extracted package to install the agent and register
   Native Messaging for the current Windows account.
2. In the Edge profile used to sign in to CPQA, open `edge://extensions`,
   enable **Developer mode**, select **Load unpacked**, and choose
   `%LOCALAPPDATA%\CPQA\Crypto Agent\extension`.
3. Reload **Manage Security Keys**. Select **Check Crypto Agent**,
   **Register signing device**, confirm with Windows Hello, and check the
   device status on the web page.

While native signing is optional, a profile with no registered device uses the
existing signing flow. Uploads in a registered profile use Crypto Agent.

The local deployment at `https://cloudsafe.cyberfortress.local` uses the Windows
x64 bundle with upstream release `v6.0.0`. The pilot Edge extension ID and its
public DER key are recorded in `config/crypto-agent/pilot-extension-identity.json`
on the development machine. Reuse both values when rebuilding to preserve the
extension identity in Edge and Django. Run from an x64 Visual Studio developer
shell at the repository root.

```powershell
$identity = Get-Content -Raw config/crypto-agent/pilot-extension-identity.json | ConvertFrom-Json
rtk python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --extension-id $identity.id --extension-key $identity.key --ref v6.0.0 --output-dir src/crypto_agent/target/windows-pilot-next
```

After copying the new installer and catalog to `config/crypto-agent/`, reload
the local environment with `rtk docker compose --project-directory . -f
docker/docker-compose.yml up -d --no-deps --force-recreate web`.

Use your organization's release signing and distribution process. For macOS
distribution with Safari, Apple Developer ID and notarization authenticate
the bundle. Document signing uses upstream ML-DSA-87, with AES-256-GCM
protecting the device private key in the Windows pilot. Expiring signing requests
bind the upload digest to an enrolled device. The device keeps the ML-DSA key
encrypted locally, with the wrapping key in the OS credential store. Starting
with agent 0.2.0, Windows 11 requires Windows Hello at enrollment and for each
signature. Keep Edge or Chrome in the foreground. Windows chooses a configured
PIN, fingerprint, or face recognition method. A cancelled or expired request
stops the operation. macOS and Linux need their own verification adapters
before they can enroll or sign. The web interface shows the document context
and Windows Hello verifies the user.

[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
· [Microsoft Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
· [Safari Web Extension distribution](https://developer.apple.com/documentation/safariservices/distributing-your-safari-web-extension)
