import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';
import { MessageChannel } from 'node:worker_threads';

const origin = 'https://cpqa.example';
const protocol = 'cpqa-crypto/v1';
const content = readFileSync(new URL('./safari-content.js', import.meta.url), 'utf8');
const page = readFileSync(new URL('../../static/js/crypto-agent.js', import.meta.url), 'utf8');

test('Safari relays the configured HTTPS top-level page through a dedicated message port', async () => {
    const window = { location: { origin }, isSecureContext: true };
    window.top = window;
    let listener;
    window.addEventListener = (name, callback) => { if (name === 'message') listener = callback; };
    window.postMessage = (data, target, ports) => {
        assert.equal(target, origin);
        listener({ data, origin, source: window, ports: structuredClone(ports, { transfer: ports }) });
    };
    const operations = [];
    const runtime = {
        sendMessage(request, reply) {
            operations.push(request.command.operation);
            reply({ ok: true, result: request.command.operation === 'probe_extension' ? { protocol } : {
                protocol, version: '0.3.1', user_verification: 'per_operation',
                verification_error: 'os_verification_unsupported',
                operations: ['enroll_signing_key', 'sign_document'],
            } });
        },
    };
    runInNewContext(content, { window, cpqaSafariOrigin: origin, browser: { runtime } });
    const unexpected = { postMessage: () => assert.fail('Rejected message returned a response') };
    const rejected = {
        data: { channel: 'cpqa-safari-agent', protocol, command: { operation: 'probe_extension' } },
        origin, source: window, ports: [unexpected],
    };
    listener({ ...rejected, origin: 'https://attacker.example' });
    listener({ ...rejected, source: {} });
    listener({ ...rejected, ports: [] });
    assert.equal(operations.length, 0);

    runInNewContext(page, {
        window, MessageChannel, setTimeout, clearTimeout,
        navigator: { userAgent: 'Mozilla/5.0 (Macintosh) Version/18.0 Safari/605.1.15',
            vendor: 'Apple Computer, Inc.', maxTouchPoints: 0 },
        document: { getElementById: () => ({ textContent: JSON.stringify({
            userId: 1, minVersion: '0.3.0', safariBundled: true,
        }) }) },
        localStorage: { getItem: () => null },
    });
    await assert.rejects(window.cpqaCryptoAgent.inspect(), { code: 'os_verification_unsupported' });
    assert.deepEqual(operations, ['probe_extension', 'get_capabilities']);
});

test('Safari content relay refuses an iframe and an unrelated deployment', () => {
    const window = { addEventListener: () => assert.fail('Unauthorized page installed the relay') };
    window.top = {};
    window.location = { origin };
    runInNewContext(content, { window, cpqaSafariOrigin: origin });
    window.top = window;
    window.location = { origin: 'https://other.example' };
    runInNewContext(content, { window, cpqaSafariOrigin: origin });
});
