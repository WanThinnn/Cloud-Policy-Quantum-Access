# Unreleased

- CoverCrypt over Vault uses the upstream authority contract v1. The public
  key reference is checked against the active authority, and setup runs
  outside the upload request. Signed and unsigned Vault writes store
  per-version scheme, envelope format, signing mode and authority identity.
- CPQA verifies authority identity before using a key cached for a schema-2
  version. A user revocation changes the cache identity even when the user's
  current attributes remain the same.
- Operators can promote a separate CoverCrypt mount and retain the previous
  authority for historical reads. The Vault KV registry binds version
  fingerprints and revisions to their original mounts.
- Owners and authorized administrators can restore a compatible version from
  file history. The verified bytes, crypto metadata and signatures are copied
  into a new version after access checks and malware scanning.
- Vault release builds resolve a single upstream commit for the plugin smoke
  test and both images, and include the source manifest in the images.
- The browser can offer local and synced providers for signing passkeys.
  CPQA verifies PRF on the selected credential before enrollment. A recovery
  phrase can unlock the existing signing key for the session or bind it to a
  replacement passkey. Provider-specific sync behavior requires device testing.
- New signing-key recovery phrases use Web Crypto randomness. Versioned
  recovery blobs use Argon2id with a random salt and retain a legacy read path.
  Users can replace a recovery phrase without changing their signing key.

Verification covers the Vault plugin deployment. Schema-2 reads require the
recorded authority and revision. After rotation, legacy CoverCrypt records
without an authority identity require operator recovery. Restore requires
compatible policy, scheme, backend, signature mode and CoverCrypt dimensions.
