import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('crypto_access', '0032_fileversion_crypto_metadata'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpublickey', name='native_device_id',
            field=models.UUIDField(blank=True, editable=False, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='fileversion', name='signing_payload',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.CreateModel(
            name='NativeSigningRequest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('payload', models.TextField()),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('consumed_at', models.DateTimeField(blank=True, null=True)),
                ('key', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                          to='crypto_access.userpublickey')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
