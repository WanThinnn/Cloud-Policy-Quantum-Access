(() => {
    const agent = window.cpqaCryptoAgent;
    if (!agent) return;
    const check = document.getElementById('crypto-agent-check');
    const enroll = document.getElementById('crypto-agent-enroll');
    const extension = document.getElementById('crypto-agent-extension');
    const downloads = document.getElementById('crypto-agent-downloads');
    const status = document.getElementById('crypto-agent-status');
    if (agent.extensionUrl) extension.href = agent.extensionUrl;

    async function suggestPackage() {
        const hints = await navigator.userAgentData?.getHighEntropyValues(['architecture', 'platform']).catch(() => null);
        const platform = hints?.platform || navigator.userAgentData?.platform || navigator.platform || '';
        const architecture = hints?.architecture;
        let target;
        if (/windows|^win/i.test(platform) && architecture !== 'arm') target = 'windows-x86_64';
        if (/linux/i.test(platform) && !/android/i.test(navigator.userAgent) && architecture !== 'arm') {
            target = 'linux-x86_64';
        }
        if (/mac/i.test(platform) && architecture) target = architecture === 'arm' ? 'macos-arm64' : 'macos-x86_64';
        if (!target) return;
        const preferred = downloads.querySelector(`[data-agent-target="${target}"]`);
        if (preferred) {
            preferred.parentElement.prepend(preferred);
            preferred.querySelector('a').append(' (suggested for this device)');
        } else {
            const note = document.createElement('p');
            note.className = 'mt-2';
            note.textContent = 'No installer is published for the detected platform.';
            downloads.appendChild(note);
        }
    }

    function display(state, version) {
        extension.hidden = !agent.extensionUrl || !['extension_unreachable', 'extension_outdated'].includes(state);
        enroll.hidden = state !== 'enrollment_required';
        if (['agent_outdated', 'host_unreachable', 'upstream_library_unavailable', 'invalid_installation',
            'upstream_abi_unavailable'].includes(state)) downloads.open = true;
        const messages = {
            ready: `Crypto Agent ${version} is ready to sign on this device.`,
            enrollment_required: `Crypto Agent ${version} is connected. Register this device to sign.`,
            extension_unconfigured: 'Your administrator has not configured the Crypto Agent browser extension.',
            extension_unreachable: 'The extension did not respond. Install or enable it in Chrome or Edge, then check again.',
            extension_outdated: 'Update the browser extension, then check again.',
            agent_outdated: 'Update Crypto Agent, then check again.',
            host_unreachable: 'The browser extension responded, but could not open Crypto Agent. Install or repair the agent, then check again.',
            invalid_installation: 'Crypto Agent could not read its installation configuration. Install the package again.',
            upstream_library_unavailable: 'Crypto Agent could not load its cryptographic library. Install the package again.',
            upstream_abi_unavailable: 'The installed cryptographic library is incompatible. Install the package again.',
            local_key_store_unavailable: 'Unlock your system credential store, then check again.',
            server_rejected_request: 'CPQA could not complete the request. Check your session and try again.',
            enrollment_expired: 'The registration request expired. Try registering again.',
            agent_timeout: 'Crypto Agent timed out. Check for a system credential prompt, then try again.',
        };
        status.textContent = messages[state] || 'Crypto Agent could not complete this request. Check the installation settings.';
    }

    async function update(register) {
        check.disabled = enroll.disabled = true;
        status.textContent = register ? 'Registering this signing device…' : 'Checking Crypto Agent…';
        try {
            if (register) await agent.enroll();
            const result = await agent.inspect();
            display(result.state, result.version);
            if (register && result.state === 'ready') window.loadKeys?.();
        } catch (error) {
            const wasVisible = !enroll.hidden;
            display(error.code);
            if (register && wasVisible) enroll.hidden = false;
        } finally {
            check.disabled = enroll.disabled = false;
        }
    }
    check.addEventListener('click', () => update(false));
    enroll.addEventListener('click', () => update(true));
    suggestPackage().catch(() => {});
})();
