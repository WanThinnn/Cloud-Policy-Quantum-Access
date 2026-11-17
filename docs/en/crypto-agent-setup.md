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

Setup copies the app into `~/Applications` and opens it once. If macOS asks
you to approve the app, open it from Finder and follow the system prompt.
In **Safari → Settings → Advanced**, enable **Show features for web developers**.
In **Developer** settings, select **Allow unsigned extensions**. Under
**Extensions**, enable **CPQA Crypto Agent**, grant it access to the CPQA site,
and reload the page. The Safari package uses Apple's local testing mode.

The macOS and Linux packages support the connection check. Enrollment and
signing require platform key protection and user verification and currently
return a verification error on these platforms.

## Publish installers

Run the manual **Build Crypto Agent installers** workflow with the CPQA HTTPS
origin. It produces a complete installer ZIP and catalog entry for Windows
x64, Linux x64, Mac Intel, and Apple silicon. The Mac ZIP includes Safari and
Chromium. No Apple account or extension ID is needed. The build derives the
stable Chromium extension ID from the public key bundled with the source.

After the workflow changes are on GitHub, dispatch it from the local CLI.
Set the shell variables for the branch and deployment origin.

```powershell
rtk gh workflow run crypto-agent.yml --ref $releaseBranch -f "origin=$cpqaOrigin"
rtk gh run list --workflow crypto-agent.yml
rtk gh run watch $runId --exit-status
rtk gh run download $runId --pattern 'crypto-agent-*' --dir agent-artifacts
```

Omit `upstream_tag` to use the current upstream release, or pass
`-f upstream_tag=v6.0.0` to use that
tag on all runners. For a local upstream source build, use `package_agent.py`
with `--source source --ref` and the upstream build dependencies.

For a local Windows pilot, run in an x64 Visual Studio developer shell with
Python and Rust available.

```powershell
rtk python src/crypto_agent/package_agent.py --origin $cpqaOrigin --ref v6.0.0 --output-dir src/crypto_agent/target/distribution
```

For a single platform, copy the installer and its `manifest.json` to
`config/crypto-agent/` on the CPQA server. For multiple platforms, assemble a
single manifest with `revision: 1` and one `packages` entry per platform.
Publish versioned packages first and replace the catalog after the files are in
place. The default Compose configuration makes that directory visible to Django
as `/config/crypto-agent`. Keep it writable only by the release operator.

In the deployment environment set `CRYPTO_AGENT_ORIGIN` to the exact origin used
for packaging. CPQA reads the Chromium extension ID and Safari availability
from the published catalog. Set
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

The local deployment at `https://cloudsafe.cyberfortress.local` uses upstream
release `v6.0.0`. The build uses the same Chromium extension ID as the Windows
pilot. Run from an x64 Visual Studio developer shell at the repository root.

```powershell
rtk python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --ref v6.0.0 --output-dir src/crypto_agent/target/windows-pilot-next
```

After copying the new installer and catalog to `config/crypto-agent/`, reload
the local environment with `rtk docker compose --project-directory . -f
docker/docker-compose.yml up -d --no-deps --force-recreate web`.

Use your organization's release signing and distribution process. The
macOS ZIP uses ad hoc code signing for local testing. Document signing
uses upstream ML-DSA-87, with AES-256-GCM
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
· [Safari Web Extension local testing](https://developer.apple.com/documentation/safariservices/building-and-testing-a-safari-web-extension)
