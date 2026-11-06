# CoverCrypt Vault Contract Fixtures

These files describe the v6.0.0 Vault plugin request/response shapes without storing a real key, ciphertext, token, or plaintext document.

- Values like `VEVTVF9...` are Base64-encoded sentinel strings, not usable cryptographic material.
- The setup/keygen/encrypt/decrypt responses are shape fixtures. A live contract test must create a fresh isolated Vault mount, call setup, then pass the real public/secret/ciphertext values returned by that test between its requests. Do not compare randomized key/ciphertext bytes against these fixtures.
- `invalid-requests.json` records stable error categories/messages to assert. Vault may wrap plugin logical errors in its HTTP `errors` array; tests should assert safe status/category, not depend on every complete error string.
- Never place `VAULT_TOKEN`, an MSK, a real ML-DSA private key, user key, ciphertext from user data, or production plaintext in this directory.

The authoritative explanation is [CoverCrypt Upstream Contract](../../../docs/en/covercrypt-vault-contract.md).
