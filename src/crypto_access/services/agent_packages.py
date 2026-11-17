"""Read the operator-published Crypto Agent download catalog."""

import json
import re
from pathlib import Path

from django.conf import settings

TARGETS = {
    'windows-x86_64': 'Windows x64',
    'linux-x86_64': 'Linux x64',
    'macos-x86_64': 'macOS Intel',
    'macos-arm64': 'macOS Apple silicon',
}
INSTALLERS = {'windows': 'msi', 'linux': 'deb', 'macos': 'pkg'}
VERSION = re.compile(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}')
MAX_CATALOG_BYTES = 32_768


def public_config(user):
    if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False) or not user.is_authenticated:
        return None

    def extension_id(value):
        return value if re.fullmatch(r'[a-p]{32}', value) else ''

    return {
        'userId': user.pk,
        'chromeExtensionId': extension_id(settings.CRYPTO_AGENT_CHROME_EXTENSION_ID),
        'edgeExtensionId': extension_id(settings.CRYPTO_AGENT_EDGE_EXTENSION_ID),
        'minVersion': settings.CRYPTO_AGENT_MIN_VERSION,
        'required': getattr(settings, 'NATIVE_SIGNING_REQUIRED', False),
    }


def package_catalog():
    directory = Path(settings.CRYPTO_AGENT_PACKAGE_DIR).resolve()
    try:
        with (directory / 'manifest.json').open('rb') as stream:
            raw = stream.read(MAX_CATALOG_BYTES + 1)
        if len(raw) > MAX_CATALOG_BYTES:
            return {}
        manifest = json.loads(raw)
        if manifest['revision'] != 1 or not isinstance(manifest['packages'], list):
            return {}
    except (KeyError, OSError, ValueError, TypeError):
        return {}

    catalog = {}
    for item in manifest['packages']:
        try:
            target, version, name, digest = (item[key] for key in ('target', 'version', 'filename', 'sha256'))
            if target not in TARGETS or not VERSION.fullmatch(version):
                continue
            platform = target.split('-', 1)[0]
            if not re.fullmatch(rf'cpqa-crypto-agent-{target}-{re.escape(version)}\.(zip|{INSTALLERS[platform]})', name):
                continue
            if not re.fullmatch(r'[0-9a-f]{64}', digest):
                continue
            path = (directory / name).resolve(strict=True)
            if path.parent != directory or not path.is_file() or target in catalog:
                continue
            catalog[target] = {'label': TARGETS[target], 'version': version, 'filename': name,
                               'sha256': digest, 'path': path}
            if path.suffix == '.zip':
                catalog[target]['install_command'] = (
                    r'powershell -File .\install.ps1' if platform == 'windows' else 'bash ./install.sh'
                )
        except (KeyError, OSError, TypeError, ValueError):
            continue
    return catalog
