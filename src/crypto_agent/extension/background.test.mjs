import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const origin = 'https://cpqa.example';
const protocol = 'cpqa-crypto/v1';
const script = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
    .replace("import { origin, safari } from './deployment.js';", '');
const request = { protocol, command: { operation: 'get_capabilities', user_id: 1, device_id: null } };

for (const safari of [false, true]) {
    test(`${safari ? 'Safari' : 'Chromium'} Native Messaging only forwards validated requests`, () => {
        let listener;
        const messages = [];
        const event = { addListener: callback => { listener = callback; } };
        const runtime = {
            id: 'extension-under-test',
            [safari ? 'onMessage' : 'onMessageExternal']: event,
            sendNativeMessage(host, message, reply) {
                messages.push({ host, message });
                reply({ ok: true });
            },
        };
        runInNewContext(script, { origin, safari, URL, [safari ? 'browser' : 'chrome']: { runtime } });
        const sender = { url: origin + '/manage/keys/', frameId: 0 };
        if (safari) sender.id = runtime.id;
        else sender.origin = origin;
        const reject = () => assert.fail('An unauthorized sender must not receive a response');
        for (const invalid of [
            { ...sender, url: 'https://attacker.example' },
            { ...sender, origin: 'null' },
            { ...sender, frameId: 1 },
            { ...sender, frameId: undefined },
            { ...sender, url: 'invalid URL' },
        ]) {
            assert.equal(listener(request, invalid, reject), false);
        }
        if (!safari) assert.equal(listener(request, { ...sender, origin: undefined }, reject), false);
        if (safari) assert.equal(listener(request, { ...sender, id: 'another-extension' }, reject), false);
        const expectInvalid = response => assert.equal(response.code, 'invalid_request');
        listener({ ...request, protocol: 'invalid' }, sender, expectInvalid);
        listener({ ...request, command: { operation: 'sign_bytes' } }, sender, expectInvalid);
        assert.equal(messages.length, 0);
        listener(request, sender, response => assert.equal(response.ok, true));
        assert.equal(messages.length, 1);
        assert.equal(messages[0].host, 'com.cpqa.crypto_agent');
        assert.equal(messages[0].message.origin, origin);
        assert.equal(messages[0].message.command.operation, request.command.operation);
    });
}
