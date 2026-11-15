const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = readFileSync(path.join(__dirname, '../src/static/js/pqc-manager.js'), 'utf8');
const argonSource = readFileSync(path.join(__dirname, '../src/static/js/lib/argon2-bundled.min.js'), 'utf8');
const credentialId = 'AQID';
const phrase = Array(24).fill('fixture').join(' ');

function fixture({ returnedId = [1, 2, 3], prfLength = 32, prfEnabled = true, legacyId = null } = {}) {
    const calls = [];
    const storage = new Map([['username', 'test_user'], ['pqc_credential_id', legacyId]]);
    const credential = (rawId, results) => ({
        rawId: Uint8Array.from(rawId),
        getClientExtensionResults: () => ({ prf: results })
    });
    const context = vm.createContext({
        console: { log() {}, error() {} },
        document: { addEventListener() {} },
        window: {
            PublicKeyCredential: {}, location: { hostname: 'files.example.test' },
            addEventListener: (name, listener) => { context[name] = listener; }
        },
        navigator: {
            userAgent: 'test-client',
            credentials: {
                async create({ publicKey }) {
                    calls.push(['create', publicKey]);
                    return credential([1, 2, 3], { enabled: prfEnabled });
                },
                async get({ publicKey }) {
                    calls.push(['get', publicKey]);
                    return credential(returnedId, { results: { first: new Uint8Array(prfLength) } });
                }
            }
        },
        localStorage: { getItem: name => storage.get(name) ?? null },
        crypto: webcrypto,
        sha3_256: { arrayBuffer: value => createHash('sha3-256').update(value).digest() },
        liboqs: async () => ({ HEAPU8: new Uint8Array(5000), _malloc: () => 1, _free() {} }),
        getCookie: () => 'fixture-csrf',
        setTimeout: () => 1,
        clearTimeout() {},
        atob,
        btoa,
        TextEncoder,
        DOMException
    });
    const manager = vm.runInContext(source + '\npqcManager', context);
    return { calls, manager, context };
}

test('enrollment verifies the exact credential and leaves provider selection to the browser', async () => {
    const { calls, manager } = fixture({ legacyId: 'BAUG' });
    const result = await manager._getPrfKey(true);
    assert.equal(result.credentialId, credentialId);
    assert.equal(result.key.extractable, false);
    const [[create, registration], [get, assertion]] = calls;
    assert.equal(create, 'create');
    assert.equal(get, 'get');
    assert.equal(registration.authenticatorSelection.authenticatorAttachment, undefined);
    assert.equal(registration.hints, undefined);
    assert.equal(assertion.hints, undefined);
    assert.equal(assertion.userVerification, 'required');
    assert.deepEqual(Array.from(assertion.allowCredentials[0].id), [1, 2, 3]);
    assert.deepEqual(Array.from(registration.extensions.prf.eval.first), Array.from(assertion.extensions.prf.eval.first));
});

test('bundled Argon2 opens legacy blobs and writes v2 with independent 16-byte salts', async () => {
    const { manager, context } = fixture();
    const browser = vm.createContext({ WebAssembly, atob, btoa, TextEncoder, TextDecoder, setTimeout });
    browser.window = browser.self = browser;
    vm.runInContext(argonSource, browser);
    context.argon2 = browser.argon2;
    const words = phrase.split(' ');
    const secret = new Uint8Array(manager.SK_LEN).fill(4);
    const old = await browser.argon2.hash({
        pass: phrase, salt: 'Cloud-Policy-Salt-test_user',
        time: 3, mem: 65536, hashLen: 32
    });
    assert.match(old.encoded, /^\$argon2d\$/);
    const oldKey = await webcrypto.subtle.importKey('raw', Uint8Array.from(old.hash), 'AES-GCM', false, ['encrypt']);
    const legacy = await manager._encryptKey(oldKey, secret);
    assert.deepEqual(new Uint8Array(await manager._unwrapRecoveryKey(words, legacy)), secret);

    const first = await manager._wrapRecoveryKey(words, () => secret);
    const second = await manager._wrapRecoveryKey(words, () => secret);
    assert.match(first, /^v2:/);
    const salt = Buffer.from(first.split(':')[1], 'base64');
    assert.equal(salt.length, 16);
    assert.notEqual(first.split(':')[1], second.split(':')[1]);
    const expected = await browser.argon2.hash({
        pass: phrase, salt: Uint8Array.from(salt), time: 3, mem: 65536, hashLen: 32,
        parallelism: 4, type: browser.argon2.ArgonType.Argon2id
    });
    const key = await webcrypto.subtle.importKey('raw', Uint8Array.from(expected.hash), 'AES-GCM', false, ['decrypt']);
    assert.deepEqual(new Uint8Array(await manager._decryptKey(key, first.split(':')[2])), secret);
    assert.deepEqual(new Uint8Array(await manager._unwrapRecoveryKey(words, first)), secret);
    await assert.rejects(manager._unwrapRecoveryKey(words, first.replace('v2:', 'v3:')), /Unsupported/);
});

test('staged recovery replacement writes only when confirmed and page hide wipes the signing buffer', async () => {
    const { manager, context } = fixture();
    await manager.initPromise;
    manager._loadSigningKey({ id: 4, pqc_public_key: 'AA==' }, new Uint8Array(manager.SK_LEN).fill(9));
    manager._getArgon2Key = async () => webcrypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
    let update;
    context.fetch = async (url, options) => {
        assert.equal(url, '/api/pki/keys/4/');
        update = JSON.parse(options.body);
        return { ok: true };
    };
    const staged = await manager.prepareRecoveryReplacement();
    assert.equal(staged.mnemonic.length, 24);
    assert.equal(update, undefined);
    await staged.save();
    assert.deepEqual(Object.keys(update), ['encrypted_pqc_sk_recovery']);
    assert.match(update.encrypted_pqc_sk_recovery, /^v2:/);
    context.pagehide();
    assert.equal(manager.isUnlocked, false);
    assert.equal(manager.module.HEAPU8[1], 0);
});

test('enrollment rejects a different credential or a missing 32-byte PRF output', async () => {
    await assert.rejects(fixture({ returnedId: [4, 5, 6] }).manager._getPrfKey(true), /different signing passkey/);
    await assert.rejects(fixture({ prfLength: 0 }).manager._getPrfKey(true),
        { name: 'NotSupportedError', message: /did not return the 32-byte PRF/ });
});

test('provider can save a credential with PRF disabled without creating a signing key', async () => {
    const { calls, manager } = fixture({ prfEnabled: false });
    await assert.rejects(manager.setup(), { name: 'NotSupportedError', message: /saved the passkey.*PRF is disabled/ });
    assert.deepEqual(calls.map(([operation]) => operation), ['create']);
    assert.equal(manager.isUnlocked, false);
});

test('explicit recovery-only setup skips WebAuthn and saves no passkey metadata', async () => {
    const { calls, manager, context } = fixture();
    await manager.initPromise;
    manager.module.HEAPU8 = new Uint8Array(10000);
    manager.module._malloc = length => length === manager.PK_LEN ? 1 : 3000;
    manager.module._OQS_SIG_ml_dsa_87_keypair = () => 0;
    manager._wrapRecoveryKey = async () => 'recovery-fixture';
    context.fetch = async (url, options) => {
        assert.equal(url, '/api/pki/keys/');
        assert.equal(options.method, 'POST');
        const payload = JSON.parse(options.body);
        assert.equal(payload.credential_id, '');
        assert.equal(payload.encrypted_pqc_sk_primary, '');
        assert.equal(payload.encrypted_pqc_sk_recovery, 'recovery-fixture');
        return { ok: true, json: async () => ({ id: 4 }) };
    };
    await manager.setup({ usePasskey: false });
    assert.deepEqual(calls, []);
    assert.equal(manager.activeKeyId, 4);
});

test('recovery replaces the wrapping and ID together and unlocks from server data in a fresh profile', async () => {
    const { manager, context } = fixture();
    const recoveryKey = await webcrypto.subtle.importKey('raw', new Uint8Array(32).fill(5), 'AES-GCM', false,
        ['encrypt', 'decrypt']);
    const secret = new Uint8Array(manager.SK_LEN).fill(7);
    const record = {
        id: 4,
        pqc_public_key: 'AA==',
        encrypted_pqc_sk_recovery: await manager._encryptKey(recoveryKey, secret),
        credential_id: 'BAUG'
    };
    manager._getArgon2Key = async () => recoveryKey;
    context.fetch = async (url, options) => {
        if (options?.method === 'PATCH') {
            assert.equal(url, '/api/pki/keys/4/');
            const data = JSON.parse(options.body);
            assert.equal(data.credential_id, credentialId);
            assert.ok(data.encrypted_pqc_sk_primary);
            Object.assign(record, data);
        }
        return { ok: true, json: async () => record };
    };
    await manager.recoverKey(phrase);
    const fresh = fixture();
    fresh.context.fetch = async () => ({ ok: true, json: async () => record });
    assert.equal(await fresh.manager.unlock(), true);
    assert.deepEqual(fresh.manager.module.HEAPU8.slice(1, 1 + secret.length), secret);
});

test('session-only recovery reads the recovery blob without replacing the passkey', async () => {
    const { calls, manager, context } = fixture();
    manager._getArgon2Key = async () => ({});
    const secret = new Uint8Array(manager.SK_LEN).fill(7);
    manager._decryptKey = async () => secret.buffer;
    context.fetch = async (url, options) => {
        assert.equal(options, undefined);
        assert.equal(url, '/api/pki/keys/active_key/');
        return { ok: true, json: async () => ({ pqc_public_key: 'AA==', encrypted_pqc_sk_recovery: 'fixture' }) };
    };
    assert.equal(await manager.recoverKey(phrase, { replacePasskey: false }), true);
    assert.deepEqual(calls, []);
    assert.equal(manager.module.HEAPU8[1], 7);
    assert.equal(secret[0], 0);
});
