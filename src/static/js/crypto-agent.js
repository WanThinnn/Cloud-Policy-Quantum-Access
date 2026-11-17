(() => {
    const node = document.getElementById('crypto-agent-config');
    if (!node) return;
    const config = JSON.parse(node.textContent);
    const protocol = 'cpqa-crypto/v1';
    const localKey = `cpqa-crypto-agent-device:${config.userId}`;
    const isSafari = /Macintosh.*Version\/.*Safari\//.test(navigator.userAgent)
        && navigator.vendor === 'Apple Computer, Inc.' && navigator.maxTouchPoints < 2;
    const isEdge = (navigator.userAgentData?.brands || []).some(({ brand }) => brand === 'Microsoft Edge')
        || /\bEdg\//.test(navigator.userAgent);
    const extensionIds = [...new Set([isEdge && config.edgeExtensionId, config.chromeExtensionId].filter(Boolean))];
    let connectedExtension;
    const runtime = window.chrome?.runtime;
    const extensionUrl = !isSafari && extensionIds[0] && (isEdge && config.edgeExtensionId
        ? `https://microsoftedge.microsoft.com/addons/detail/${extensionIds[0]}`
        : `https://chromewebstore.google.com/detail/${extensionIds[0]}`);

    class AgentError extends Error {
        constructor(code) {
            super(code);
            this.code = code;
        }
    }

    function verificationMessage(code) {
        return {
            os_verification_cancelled: 'System verification was cancelled. Try again when you are ready.',
            os_verification_denied: 'System verification failed. Try again with your configured sign-in method.',
            os_verification_unavailable: 'System verification is unavailable. Check the Crypto Agent setup for this operating system.',
            os_verification_busy: 'Close any other verification prompt and try again.',
            os_verification_browser_focus: 'Bring this browser window to the front and try again.',
            os_verification_unsupported: 'Crypto Agent is connected. Native signing is unavailable on this platform.',
            signing_intent_expired: 'The request expired. Start again to get a new verification prompt.',
            agent_timeout: 'Crypto Agent timed out. Close any pending verification prompt and try again.',
        }[code];
    }

    function send(extensionId, command) {
        if (isSafari ? (!window.isSecureContext || window.top !== window) : !runtime?.sendMessage) {
            return Promise.reject(new AgentError('extension_unreachable'));
        }
        return new Promise((resolve, reject) => {
            const interactive = ['enroll_signing_key', 'sign_document'].includes(command.operation);
            const probe = command.operation === 'probe_extension';
            const timeout = interactive ? 125000 : probe ? 5000 : 45000;
            const channel = isSafari ? new MessageChannel() : null;
            const timer = setTimeout(() => {
                channel?.port1.close();
                reject(new AgentError(probe ? 'extension_unreachable' : 'agent_timeout'));
            }, timeout);
            function reply(response) {
                clearTimeout(timer);
                channel?.port1.close();
                if (!response) reject(new AgentError('extension_unreachable'));
                else if (!response.ok) reject(new AgentError(response.code));
                else resolve(response.result);
            }
            try {
                if (channel) {
                    channel.port1.onmessage = event => reply(event.data);
                    window.postMessage({ channel: 'cpqa-safari-agent', protocol, command },
                        window.location.origin, [channel.port2]);
                } else {
                    runtime.sendMessage(extensionId, { protocol, command }, response => {
                        reply(runtime.lastError ? null : response);
                    });
                }
            } catch {
                channel?.port2.close();
                reply(null);
            }
        });
    }

    async function connectExtension() {
        const candidates = isSafari ? (config.safariBundled ? [null] : []) : extensionIds;
        if (!candidates.length) throw new AgentError('extension_unconfigured');
        for (const extensionId of candidates) {
            try {
                const extension = await send(extensionId, { operation: 'probe_extension' });
                if (extension?.protocol !== protocol) throw new AgentError('extension_outdated');
                return extensionId;
            } catch (error) {
                if (error.code !== 'extension_unreachable') throw error;
            }
        }
        throw new AgentError('extension_unreachable');
    }

    async function call(command) {
        if (connectedExtension === undefined) connectedExtension = await connectExtension();
        return send(connectedExtension, command);
    }

    async function api(action, data) {
        const url = action === 'prepare_document_signature'
            ? '/api/storage/files/prepare_document_signature/' : `/api/pki/keys/${action}/`;
        const token = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/)?.[1] || '';
        const response = await fetch(url, data === undefined ? {} : {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': decodeURIComponent(token) },
            body: JSON.stringify(data),
        });
        if (!response.ok) throw new AgentError('server_rejected_request');
        return response.json();
    }

    function compatible(result) {
        const format = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/;
        if (result?.protocol !== protocol || !format.test(result.version)
            || !format.test(config.minVersion) || !Array.isArray(result.operations)
            || !['enroll_signing_key', 'sign_document'].every(value => result.operations.includes(value))) {
            return false;
        }
        const current = result.version.split('.').map(Number);
        const required = config.minVersion.split('.').map(Number);
        const difference = current.map((part, index) => part - required[index]).find(value => value !== 0);
        return difference === undefined || difference > 0;
    }

    async function inspect() {
        connectedExtension = undefined;
        connectedExtension = await connectExtension();
        const deviceId = localStorage.getItem(localKey);
        const result = await call({ operation: 'get_capabilities', user_id: config.userId, device_id: deviceId });
        if (!compatible(result) || result.user_verification !== 'per_operation') return { state: 'agent_outdated' };
        if (result.verification_error) throw new AgentError(result.verification_error);
        if (deviceId && result.has_key) {
            const devices = await api('signing_devices');
            if (devices.some(device => device.device_id === deviceId && device.status === 'active')) {
                return { state: 'ready', version: result.version, deviceId };
            }
        }
        return { state: 'enrollment_required', version: result.version };
    }

    let pendingEnrollment;
    async function enroll() {
        if (!pendingEnrollment) {
            const intent = await api('prepare_enrollment', {});
            const proof = await call({ operation: 'enroll_signing_key', payload: intent.payload });
            pendingEnrollment = {
                request_id: intent.request_id,
                public_key: proof.public_key,
                signature: proof.signature,
                deviceId: JSON.parse(intent.payload).device_id,
                created: Date.now(),
            };
        }
        const { created, deviceId, ...proof } = pendingEnrollment;
        if (Date.now() - created > 175000) {
            pendingEnrollment = undefined;
            throw new AgentError('enrollment_expired');
        }
        try {
            const result = await api('complete_enrollment', proof);
            if (result.device_id !== deviceId) throw new AgentError('server_rejected_request');
        } catch (error) {
            const devices = await api('signing_devices');
            if (!devices.some(device => device.device_id === deviceId && device.status === 'active')) {
                throw error;
            }
        }
        localStorage.setItem(localKey, deviceId);
        pendingEnrollment = undefined;
    }

    async function signDocument(file, target, newVersion) {
        const status = await inspect();
        if (status.state !== 'ready') throw new AgentError(status.state);
        const intent = await api('prepare_document_signature', {
            bucket_name: 'documents', file_path: target, is_new_version: newVersion,
            sha3_256: sha3_256(await file.arrayBuffer()), device_id: status.deviceId,
        });
        const result = await call({ operation: 'sign_document', payload: intent.payload });
        return { requestId: intent.request_id, signature: result.signature };
    }

    function shouldSignDocument() {
        return config.required || Boolean(localStorage.getItem(localKey));
    }

    window.cpqaCryptoAgent = {
        extensionUrl, isSafari, inspect, enroll, signDocument, shouldSignDocument, verificationMessage,
    };
})();
