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

Verification covers the Vault plugin deployment. Schema-2 reads require the
recorded authority and revision. After rotation, legacy CoverCrypt records
without an authority identity require operator recovery. Restore requires
compatible policy, scheme, backend, signature mode and CoverCrypt dimensions.
