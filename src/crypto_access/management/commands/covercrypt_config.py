"""Inspect configuration or reconcile verified public metadata; never clear guards."""
import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from crypto_access.services.covercrypt_config import build_covercrypt_configuration, validate_vault_mount
from crypto_access.services.cpabe_service import COVERCRYPT_MANIFEST_KEY, COVERCRYPT_VAULT_MOUNT, CPABEService
from crypto_access.services.vault_service import vault_service


class Command(BaseCommand):
    help = 'Inspect, initialize, reconcile or promote CoverCrypt Vault authorities.'

    def add_arguments(self, parser):
        parser.add_argument('--check-vault', action='store_true', help='Read and validate the recorded manifest and live public authority.')
        parser.add_argument('--initialize-vault', action='store_true', help='Initialize a newly provisioned CoverCrypt mount with the create-only guard.')
        parser.add_argument('--rotate-vault', action='store_true', help='Promote a pre-provisioned authority on a separate mount and retain the current authority.')
        parser.add_argument('--expected-fingerprint', help='Current authority fingerprint required for promotion.')
        parser.add_argument('--reconcile-vault', action='store_true', help='Read the existing authority and atomically repair matching public KV metadata. Never calls setup.')
        parser.add_argument('--write-manifest', action='store_true', help='Alias for --reconcile-vault; no unverified manifest writes.')
        parser.add_argument('--recover-failed-initialization', action='store_true', help='Retired unsafe guard-clearing option; use --reconcile-vault.')
        parser.add_argument('--confirm-no-authority', action='store_true', help='Retired option; a missing authority response does not authorize clearing a guard.')
        parser.add_argument('--keyset-id', help='Approved keyset identifier (currently primary).')
        parser.add_argument('--vault-mount', help='Current mount for checks or new mount for rotation.')

    def handle(self, *args, **options):
        if options['recover_failed_initialization'] or options['confirm_no_authority']:
            raise CommandError('Clearing initialization guards is no longer supported. Use --reconcile-vault; a missing authority fails closed.')
        try:
            configuration = build_covercrypt_configuration()
            reconcile = options['reconcile_vault'] or options['write_manifest']
            operations = (options['check_vault'], reconcile, options['initialize_vault'], options['rotate_vault'])
            if sum(operations) > 1:
                raise CommandError('Choose one Vault operation.')
            result = {'configuration': configuration.as_dict()}
            if any(operations):
                if not getattr(settings, 'USE_VAULT_ABE_PLUGIN', False):
                    raise CommandError('Vault authority reconciliation requires Vault plugin mode.')
                if options['keyset_id'] != 'primary':
                    raise CommandError('Vault operations require --keyset-id primary.')
                service = CPABEService.vault_metadata_client()
                if options['rotate_vault']:
                    mount = validate_vault_mount(options['vault_mount'])
                    if not options['expected_fingerprint']:
                        raise CommandError('Rotation requires --expected-fingerprint for the current authority.')
                    result['keyset_manifest'] = service.rotate_covercrypt_authority(mount, options['expected_fingerprint'])
                else:
                    state = service._covercrypt_authority_state()
                    initialized = state.get(COVERCRYPT_MANIFEST_KEY) is not None
                    active_mount = service._covercrypt_record_mount(state) if initialized else COVERCRYPT_VAULT_MOUNT
                    mount = validate_vault_mount(options['vault_mount'] or active_mount)
                    if mount != active_mount:
                        raise CommandError('The requested mount is not the active CoverCrypt mount.')
                    headers = {'X-Vault-Token': vault_service.get_token}
                    if reconcile or options['initialize_vault']:
                        service._ensure_covercrypt_keyset(
                            bool(getattr(settings, 'ENABLE_PQC_FEATURES', False)),
                            headers, allow_setup=options['initialize_vault'] and not initialized,
                        )
                        state = service._covercrypt_authority_state()
                    route = service._verify_covercrypt_record(state, headers)
                    if route.mount != mount or route.configuration.fingerprint != configuration.fingerprint:
                        raise CommandError('The active CoverCrypt mount or configuration differs from the requested schema.')
                    result['keyset_manifest'] = json.loads(service._covercrypt_record(route)[COVERCRYPT_MANIFEST_KEY])
            self.stdout.write(json.dumps(result, indent=2))
        except CommandError:
            raise
        except Exception as exc:
            raise CommandError('CoverCrypt public metadata could not be verified/reconciled; authority and guards were not reset.') from exc
