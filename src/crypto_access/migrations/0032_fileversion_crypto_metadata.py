from django.db import migrations, models


def backfill_explicit_plaintext(apps, schema_editor):
    # An empty recorded policy is a known plaintext write/removal. NULL means unknown
    # for historical auto-created versions and cannot be safely backfilled as plaintext.
    Version = apps.get_model('crypto_access', 'FileVersion')
    Version.objects.using(schema_editor.connection.alias).filter(cpabe_policy='', crypto_metadata={}).update(
        crypto_metadata={'schema': 1, 'scheme': None, 'format': 'plaintext', 'pqc_signed': False, 'backend': 'none'},
    )


class Migration(migrations.Migration):
    dependencies = [('crypto_access', '0031_activesession_refresh_lifecycle')]
    operations = [
        migrations.AddField(
            model_name='fileversion', name='crypto_metadata', field=models.JSONField(blank=True, default=dict),
        ),
        migrations.RunPython(backfill_explicit_plaintext, migrations.RunPython.noop),
    ]
