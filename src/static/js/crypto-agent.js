(() => {
    const node = document.getElementById('crypto-agent-config');
    if (!node) return;
    const config = JSON.parse(node.textContent);
    const protocol = 'cpqa-crypto/v1';
    const localKey = `cpqa-crypto-agent-device:${config.userId}`;
    const browser = (navigator.userAgentData?.brands || []).some(({ brand }) => brand === 'Microsoft Edge')
        || /\bEdg\//.test(navigator.userAgent) ? 'edge' : 'chrome';
    const extensionId = browser === 'edge'
        ? config.edgeExtensionId || config.chromeExtensionId : config.chromeExtensionId;
    const extensionUrl = extensionId && (browser === 'edge' && config.edgeExtensionId
        ? `https://microsoftedge.microsoft.com/addons/detail/${extensionId}`
        : `https://chromewebstore.google.com/detail/${extensionId}`);

    class AgentError extends Error {
        constructor(code) {
            super(code);
            this.code = code;
        }
    }

    function call(command) {
        if (!extensionId) return Promise.reject(new AgentError('extension_unconfigured'));
        if (!window.chrome?.runtime?.sendMessage) return Promise.reject(new AgentError('extension_unreachable'));
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new AgentError('agent_timeout')), 45000);
            try {
                chrome.runtime.sendMessage(extensionId, { protocol, command }, response => {
                    clearTimeout(timer);
                    if (chrome.runtime.lastError || !response) {
                        reject(new AgentError('extension_unreachable'));
                    } else if (!response.ok) {
                        reject(new AgentError(response.code));
                    } else {
                        resolve(response.result);
                    }
                });
            } catch {
                clearTimeout(timer);
                reject(new AgentError('extension_unreachable'));
            }
        });
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
        const extension = await call({ operation: 'probe_extension' });
        if (extension?.protocol !== protocol) throw new AgentError('extension_outdated');
        const deviceId = localStorage.getItem(localKey);
        const result = await call({ operation: 'get_capabilities', user_id: config.userId, device_id: deviceId });
        if (!compatible(result)) return { state: 'agent_outdated' };
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

    window.cpqaCryptoAgent = { extensionUrl, inspect, enroll, signDocument, shouldSignDocument };
})();
