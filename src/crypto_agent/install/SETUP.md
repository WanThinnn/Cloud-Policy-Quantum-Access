# Set up CPQA Crypto Agent

1. Extract the whole ZIP to a folder on this computer.
2. Open a terminal in that folder and run setup once as your normal user.
   - Windows PowerShell: `powershell -NoProfile -File .\setup.ps1`
   - macOS or Linux: `bash ./setup.sh`
3. Enable the extension in the browser profile you use for CPQA.
4. Sign in to CPQA, open **Security Keys**, and choose **Check Crypto Agent**.

## Chrome, Edge, Brave, and other Chromium browsers

1. Open your browser's **Extensions** page.
   - Chrome and Chromium: `chrome://extensions`
   - Microsoft Edge: `edge://extensions`
   - Brave: `brave://extensions`
   - Vivaldi: `vivaldi://extensions`
2. Turn on **Developer mode** and choose **Load unpacked**.
3. Select the installed `extension` folder printed by setup, then reload CPQA.
   Use that local folder so the extension remains available after you delete
   the extracted ZIP folder.

If your browser administrator disables unpacked extensions or Native Messaging,
ask them to approve the extension for your profile. Chromium variants may use
a different native host location or restrict access to desktop native hosts.

## Safari on macOS

Use these steps if your Mac package includes Safari support.

Open **Safari → Settings → Extensions**, enable **CPQA Crypto Agent**, and
allow it to access your CPQA site. Reload the CPQA tab.
