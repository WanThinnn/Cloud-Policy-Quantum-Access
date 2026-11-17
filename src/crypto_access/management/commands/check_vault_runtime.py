from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from crypto_access.models import FileVersion
from crypto_access.services.vault_service import vault_service


class Command(BaseCommand):
    help = 'Verify the production Vault runtime token and read-only key metadata.'

    def handle(self, *args, **options):
        if not vault_service.runtime_only:
            raise CommandError('Production Vault runtime token configuration is required.')
        try:
            vault_service.check_runtime_token()
            required = {'CPABE_PK_AC17', 'CPABE_PK_TKN20', 'MASTER_FIELD_ENCRYPTION_KEY'}
            state = vault_service.get_secrets(required)
            if not all(state.get(key) for key in required):
                raise ValueError()
        except Exception:
            raise CommandError('Vault is unavailable or runtime metadata has not been provisioned.') from None
        if (FileVersion._meta.db_table in connection.introspection.table_names() and
                FileVersion.objects.filter(crypto_metadata__backend='native').exists()):
            raise CommandError('Native ciphertext history requires an operator migration before Vault-only cutover.')
        self.stdout.write('Production Vault runtime token and metadata are ready.')
