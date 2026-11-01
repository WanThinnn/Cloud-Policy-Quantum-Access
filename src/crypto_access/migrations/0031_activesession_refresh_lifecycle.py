from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('crypto_access', '0030_uploadedfile_abe_scheme_alter_accesspolicy_action_and_more')]

    operations = [
        migrations.AddField(
            model_name='activesession', name='refresh_jti',
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='activesession', name='expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
