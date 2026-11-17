# Set up Crypto Agent

Open **Manage Security Keys**, then select **Check Crypto Agent**. Follow the
action shown for the browser or the device. The download list includes only
installers published by your administrator. If CPQA suggests a package, verify
the architecture before downloading it.
If the check button is disabled, an administrator must enable Crypto Agent for this deployment.

1. Install the company-provided extension in Chrome or Edge and reload CPQA.
2. Download, verify the displayed SHA-256, and extract the package for your OS.
   For a pilot ZIP, run `powershell -File .\install.ps1` on Windows or
   `bash ./install.sh` on macOS or Linux from the extracted directory. The pilot
   scripts install for the current OS user and register Native Messaging.
3. Return to CPQA. Select **Check Crypto Agent**, then **Register signing
   device**. Recheck after switching browser profiles. Each profile uses its
   own local registration reference.

## Publish installers

Run the manual **Build Crypto Agent installers** workflow with the CPQA HTTPS
origin and the Chrome/Edge extension IDs. The workflow builds native agents and
emits installer ZIPs, an extension ZIP, and a catalog entry per platform. The
extension ZIP can be used for managed deployment. An unpacked pilot needs the
Base64 DER public key that corresponds to its configured extension ID. Publish
the extension through Chrome Web Store, Microsoft Edge Add-ons, or enterprise
browser policy. Store URLs in the UI assume the corresponding extension has
been published to the store.

For a local Windows pilot, run in an x64 Visual Studio developer shell with
Python and Rust available. Use your deployed extension ID in the command.

```powershell
python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --extension-id YOUR_EXTENSION_ID --ref v6.0.0 --output-dir src/crypto_agent/target/distribution
```

For a single platform, copy the installer and its `manifest.json` to
`config/crypto-agent/` on the CPQA server. For multiple platforms, assemble a
single manifest with `revision: 1` and one `packages` entry per platform.
Publish versioned packages first and replace the catalog after the files are in
place. The default Compose configuration makes that directory visible to Django
as `/config/crypto-agent`. Keep it writable only by the release operator.

In the deployment environment set `CRYPTO_AGENT_ORIGIN` to the exact origin used
for packaging. Set `CRYPTO_AGENT_CHROME_EXTENSION_ID` and optionally
`CRYPTO_AGENT_EDGE_EXTENSION_ID`. Set `CRYPTO_AGENT_MIN_VERSION` to the minimum
compatible agent version. Apply the Django migrations, recreate the web
container with `NATIVE_SIGNING_ENABLED=true`, and verify setup with a pilot user.
Keep `NATIVE_SIGNING_REQUIRED=false` until the distribution and onboarding
paths have been verified for users.

### First Edge setup on a Windows pilot device

1. Run `install.ps1` from the extracted agent package to register Native
   Messaging for the current Windows account.
2. Extract `cpqa-crypto-agent-extension.zip` to a stable folder, such as
   `%LOCALAPPDATA%\CPQA\Crypto Agent\extension`. Keep the folder after adding
   the extension.
3. In the Edge profile used to sign in to CPQA, open `edge://extensions`,
   enable **Developer mode**, select **Load unpacked**, and choose the extracted
   folder. This workflow is for an internally built pilot extension.
4. Reload **Manage Security Keys**. Select **Check Crypto Agent**,
   **Register signing device**, then recheck for **Ready**.

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
python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --extension-id $identity.id --extension-key $identity.key --ref v6.0.0 --output-dir src/crypto_agent/target/windows-pilot-next
```

After copying the new installer and catalog to `config/crypto-agent/`, reload
the local environment with `rtk docker compose --project-directory . -f
docker/docker-compose.yml up -d --no-deps --force-recreate web`.

The generated ZIPs are for pilots. Use your organization's release signing
and distribution process for production installers. Expiring signing requests
bind the upload digest to an enrolled device. The device keeps the ML-DSA key
encrypted locally, with the wrapping key in the OS credential store. Hardware
backing and an OS confirmation prompt on every signature are still pending.
The web interface provides the document context shown to the user.

[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
· [Microsoft Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
