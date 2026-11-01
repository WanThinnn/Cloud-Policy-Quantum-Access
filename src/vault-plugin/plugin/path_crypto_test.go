package abe

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// All keys and plaintext belong to an isolated in-memory backend, never the deployed Vault.
func TestVersionCryptoMetadata(t *testing.T) {
	for _, scheme := range []string{"ac17", "tkn20"} {
		t.Run(scheme, func(t *testing.T) {
			ctx := context.Background()
			config := logical.TestBackendConfig(t)
			config.StorageView = &logical.InmemStorage{}
			backend, err := Factory(ctx, config)
			if err != nil {
				t.Fatal("backend initialization failed")
			}
			call := func(path string, data map[string]interface{}) *logical.Response {
				t.Helper()
				response, err := backend.HandleRequest(ctx, &logical.Request{
					Operation: logical.UpdateOperation, Path: path, Storage: config.StorageView, Data: data,
				})
				if err != nil || response == nil || response.IsError() {
					t.Fatalf("isolated %s operation failed", path)
				}
				return response
			}
			setup := call("setup", map[string]interface{}{"scheme": scheme, "pqc": true})
			key := call("genkey", map[string]interface{}{"scheme": scheme, "attributes": "department:it"})
			plain := base64.StdEncoding.EncodeToString([]byte("isolated-version-roundtrip"))
			for _, signed := range []bool{false, true} {
				encrypted := call("encrypt", map[string]interface{}{
					"scheme": scheme, "public_key": setup.Data["public_key"],
					"policy": "department:it", "plaintext": plain, "sign": signed,
				})
				metadata := encrypted.Data["crypto_metadata"].(map[string]interface{})
				if metadata["scheme"] != scheme || metadata["pqc_signed"] != signed || metadata["format"] != "hybrid-v2" {
					t.Fatal("encryption metadata does not reflect actual ciphertext mode")
				}
				payload := map[string]interface{}{"ciphertext": encrypted.Data["ciphertext"], "secret_key": key.Data["secret_key"]}
				if signed {
					payload["pqc_public_key"] = setup.Data["pqc_public_key"]
				}
				decrypted := call("decrypt", payload)
				if decrypted.Data["plaintext"] != plain {
					t.Fatal("isolated version roundtrip failed")
				}
			}
		})
	}
}
