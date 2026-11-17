/* Origin and the extension identity are provisioned with the deployment. */
import { origin } from './deployment.js';

const protocol = 'cpqa-crypto/v1';
const host = 'com.cpqa.crypto_agent';

function validCommand(command) {
    if (!command || typeof command !== 'object') return false;
    const fields = Object.keys(command).sort().join(',');
    switch (command.operation) {
        case 'get_capabilities':
            return fields === 'device_id,operation,user_id'
                && Number.isSafeInteger(command.user_id) && command.user_id > 0
                && (command.device_id === null || /^[0-9a-f-]{36}$/.test(command.device_id));
        case 'enroll_signing_key':
        case 'sign_document':
            return fields === 'operation,payload'
                && typeof command.payload === 'string' && command.payload.length <= 4096;
        default:
            return false;
    }
}

chrome.runtime.onMessageExternal.addListener((message, sender, reply) => {
    if (sender.origin !== origin || !sender.url || new URL(sender.url).origin !== origin
        || sender.frameId !== 0) return false;
    if (message?.command?.operation === 'probe_extension') {
        reply({ ok: true, result: { protocol } });
        return false;
    }
    if (message?.protocol !== protocol || !validCommand(message.command)) {
        reply({ ok: false, code: 'invalid_request' });
        return false;
    }
    chrome.runtime.sendNativeMessage(host, { protocol, origin, command: message.command }, response => {
        if (chrome.runtime.lastError || !response) {
            reply({ ok: false, code: 'host_unreachable' });
            return;
        }
        reply(response);
    });
    return true;
});
