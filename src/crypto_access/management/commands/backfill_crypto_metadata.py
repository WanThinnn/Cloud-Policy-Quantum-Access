"""Recover unknown version metadata only from an explicit, blob-bound evidence manifest."""
import hashlib
import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from crypto_access.models import FileVersion
from crypto_access.services.storage import get_storage_service
from crypto_access.services.version_crypto import inspect_header, validate_metadata


class Command(BaseCommand):
    help = 'Report unknown crypto metadata, or validate/apply an evidence manifest. Dry-run is the default.'

    def add_arguments(self, parser):
        parser.add_argument('--manifest', type=Path)
        parser.add_argument('--apply', action='store_true')

    def handle(self, *args, **options):
        if options['manifest'] is None:
            if options['apply']:
                raise CommandError('--apply requires an evidence manifest.')
            self.stdout.write(f'Unknown crypto metadata: {FileVersion.objects.filter(crypto_metadata={}).count()}')
            return
        try:
            entries = json.loads(options['manifest'].read_text(encoding='utf-8'))
            if not isinstance(entries, list) or not entries or len(entries) > 10000:
                raise ValueError
            ids = [entry['version_id'] for entry in entries]
            if any(type(pk) is not int for pk in ids) or len(set(ids)) != len(ids):
                raise ValueError
        except Exception:
            raise CommandError('Invalid metadata manifest; expected unique version IDs and evidence entries.') from None
        service = get_storage_service()
        pending = []
        # Validate the complete manifest before activating any metadata.
        with transaction.atomic():
            for entry in entries:
                try:
                    version = FileVersion.objects.select_for_update().select_related('file__bucket').get(
                        pk=entry['version_id'])
                    if not isinstance(entry.get('evidence'), str) or not entry['evidence'].strip():
                        raise ValueError
                    value = validate_metadata(entry['crypto_metadata'])
                    if version.crypto_metadata and version.crypto_metadata != value:
                        raise ValueError
                    blob = service.download_file(version.file.bucket.name, version.physical_path)
                    if hashlib.sha256(blob).hexdigest() != entry['ciphertext_sha256']:
                        raise ValueError
                    if value['format'] != 'plaintext':
                        header = inspect_header(blob)
                        if any(value[key] != header[key] for key in ('scheme', 'format')):
                            raise ValueError
                    pending.append((version, value))
                except Exception:
                    raise CommandError(f"Version {entry['version_id']}: evidence/blob/metadata validation failed.") from None
            if options['apply']:
                for version, value in pending:
                    version.crypto_metadata = value
                    version.save(update_fields=['crypto_metadata'])
        verb = 'Applied' if options['apply'] else 'Validated (dry-run)'
        self.stdout.write(f'{verb}: {len(pending)} version(s). No file bytes or keys were changed.')
