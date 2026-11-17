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


def chromium_extension_id(value):
    return value if isinstance(value, str) and re.fullmatch(r'[a-p]{32}', value) else ''


def catalog_extension_id(catalog, field):
    identities = {package[field] for package in catalog.values() if package.get(field)}
    return identities.pop() if len(identities) == 1 else ''


def public_config(user, catalog=None):
    if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False) or not user.is_authenticated:
        return None

    chrome_id = chromium_extension_id(getattr(settings, 'CRYPTO_AGENT_CHROME_EXTENSION_ID', ''))
    if catalog is None and getattr(settings, 'CRYPTO_AGENT_PACKAGE_DIR', None):
        catalog = package_catalog()
    catalog = catalog or {}

    return {
        'userId': user.pk,
        'chromeExtensionId': chrome_id or catalog_extension_id(catalog, 'chromium_extension_id'),
        'edgeExtensionId': chromium_extension_id(getattr(settings, 'CRYPTO_AGENT_EDGE_EXTENSION_ID', '')),
        'safariBundled': any(package.get('safari_bundled') for package in catalog.values()),
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
    configured_origin = getattr(settings, 'CRYPTO_AGENT_ORIGIN', '')
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
            if item.get('origin') and configured_origin and item['origin'] != configured_origin:
                continue
            path = (directory / name).resolve(strict=True)
            if path.parent != directory or not path.is_file() or target in catalog:
                continue
            catalog[target] = {'label': TARGETS[target], 'version': version, 'filename': name,
                               'sha256': digest, 'path': path}
            if platform == 'macos' and item.get('safari_bundled') is True:
                catalog[target]['safari_bundled'] = True
            chromium_id = chromium_extension_id(item.get('chromium_extension_id'))
            if chromium_id:
                catalog[target]['chromium_extension_id'] = chromium_id
            if path.suffix == '.zip':
                setup = 'setup.ps1' if platform == 'windows' else 'setup.sh'
                if item.get('setup_script') == setup:
                    catalog[target]['setup_script'] = setup
                    catalog[target]['install_command'] = (
                        r'powershell -NoProfile -File .\setup.ps1' if platform == 'windows' else 'bash ./setup.sh'
                    )
                else:
                    catalog[target]['install_command'] = (
                        r'powershell -File .\install.ps1' if platform == 'windows' else 'bash ./install.sh'
                    )
        except (KeyError, OSError, TypeError, ValueError):
            continue
    return catalog
