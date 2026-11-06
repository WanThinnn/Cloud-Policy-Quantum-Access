"""Inspect or explicitly persist CoverCrypt keyset metadata."""

import json

from django.core.management.base import BaseCommand, CommandError

from crypto_access.services.covercrypt_config import (
    CoverCryptConfigurationError,
    build_covercrypt_configuration,
    build_keyset_manifest,
    manifest_key,
    verify_keyset_manifest,
)
from crypto_access.services.vault_service import vault_service


class Command(BaseCommand):
    help = "Validate the deployment-owned CoverCrypt configuration and keyset manifest."

    def add_arguments(self, parser):
        parser.add_argument(
            "--check-vault",
            action="store_true",
            help="Require a compatible manifest for the configured CoverCrypt keyset in Vault.",
        )
        parser.add_argument(
            "--write-manifest",
            action="store_true",
            help="Explicitly write the non-secret manifest; never creates or rotates a Vault authority.",
        )
        parser.add_argument(
            "--recover-failed-initialization",
            action="store_true",
            help="Clear a matching incomplete first-setup guard after operator verification.",
        )
        parser.add_argument(
            "--confirm-no-authority",
            action="store_true",
            help="Confirm the CoverCrypt Vault mount contains no authority and can safely be initialized.",
        )
        parser.add_argument("--keyset-id", help="The operator-approved identifier for this Vault authority.")
        parser.add_argument("--vault-mount", help="The Vault mount containing this authority, without a trailing slash.")

    def handle(self, *args, **options):
        try:
            configuration = build_covercrypt_configuration()
        except CoverCryptConfigurationError as exc:
            raise CommandError(str(exc)) from exc

        needs_manifest = options["check_vault"] or options["write_manifest"]
        needs_identity = needs_manifest or options["recover_failed_initialization"]
        if needs_identity and (not options["keyset_id"] or not options["vault_mount"]):
            raise CommandError("Vault operations require --keyset-id and --vault-mount")
        manifest = None
        key = None
        if needs_identity:
            try:
                manifest = build_keyset_manifest(options["keyset_id"], options["vault_mount"], configuration)
                key = manifest_key(options["keyset_id"])
            except CoverCryptConfigurationError as exc:
                raise CommandError(str(exc)) from exc

        if options["recover_failed_initialization"]:
            if not options["confirm_no_authority"]:
                raise CommandError(
                    "Recovery requires --confirm-no-authority after verifying the plugin mount has no saved authority."
                )
            if options["keyset_id"] != "primary" or options["vault_mount"] != "abe_covercrypt":
                raise CommandError("Failed-initialization recovery is limited to primary at abe_covercrypt.")
            if (vault_service.get_secret(key) is not None or
                    vault_service.get_secret("CPABE_PK_COVERCRYPT") is not None or
                    vault_service.get_secret("PQC_PK_COVERCRYPT") is not None):
                raise CommandError("CoverCrypt metadata or public keys exist in KV; refusing to clear its setup guard.")
            if vault_service.get_secret("COVERCRYPT_MOUNT_CREATED") != "abe_covercrypt":
                raise CommandError("The mount was not recorded as newly created; refusing failed-setup recovery.")
            marker_key = "COVERCRYPT_KEYSET_INITIALIZING_primary"
            marker_raw = vault_service.get_secret(marker_key)
            try:
                marker_data = json.loads(marker_raw) if isinstance(marker_raw, str) else marker_raw
            except (TypeError, ValueError) as exc:
                raise CommandError("The initialization guard is not valid JSON; refusing recovery.") from exc
            if (not isinstance(marker_data, dict) or marker_data.get("status") != "initializing" or
                    marker_data.get("config_fingerprint") != configuration.fingerprint):
                raise CommandError("The initialization guard does not match this active configuration; refusing recovery.")
            if not vault_service.put_secret(marker_key, None):
                raise CommandError("Vault did not clear the failed CoverCrypt initialization guard.")
            self.stdout.write(self.style.SUCCESS("Cleared the matching failed-initialization guard."))
            return

        if options["check_vault"]:
            stored_manifest = vault_service.get_secret(key)
            if stored_manifest is None:
                raise CommandError(f"No CoverCrypt keyset manifest exists in Vault at key '{key}'")
            try:
                verify_keyset_manifest(stored_manifest, options["keyset_id"], options["vault_mount"], configuration)
            except CoverCryptConfigurationError as exc:
                raise CommandError(str(exc)) from exc

        if options["write_manifest"]:
            existing = vault_service.get_secret(key)
            if existing is not None:
                try:
                    verify_keyset_manifest(existing, options["keyset_id"], options["vault_mount"], configuration)
                except CoverCryptConfigurationError as exc:
                    raise CommandError(
                        "Refusing to overwrite an incompatible CoverCrypt keyset manifest: " + str(exc)
                    ) from exc
            if not vault_service.put_secret(key, json.dumps(manifest, sort_keys=True, separators=(",", ":"))):
                raise CommandError("Vault did not accept the CoverCrypt keyset manifest")

        response = {"configuration": configuration.as_dict()}
        if manifest is not None:
            response["keyset_manifest"] = manifest
        self.stdout.write(json.dumps(response, indent=2))
