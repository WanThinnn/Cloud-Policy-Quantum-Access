(() => {
    if (window.top !== window || window.location.origin !== cpqaSafariOrigin) return;

    window.addEventListener('message', event => {
        const message = event.data;
        if (event.source !== window || event.origin !== cpqaSafariOrigin || event.ports.length !== 1
            || message?.channel !== 'cpqa-safari-agent' || message.protocol !== 'cpqa-crypto/v1') return;

        const port = event.ports[0];
        browser.runtime.sendMessage({ protocol: message.protocol, command: message.command }, response => {
            port.postMessage(browser.runtime.lastError || !response ? { ok: false, code: 'host_unreachable' } : response);
            port.close();
        });
    });
})();
