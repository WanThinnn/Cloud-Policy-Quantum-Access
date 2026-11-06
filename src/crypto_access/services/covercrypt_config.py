"""Build the CoverCrypt setup document from the authoritative ABAC schema.

CoverCrypt's Vault setup accepts one JSON document. CPQA derives that document
from active enum AttributeDefinition rows seeded during initialization; it does
not duplicate those dimensions in environment variables or runtime settings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from ..models import AttributeDefinition, UserType, UserProfile


MANIFEST_FORMAT_VERSION = 1
MANIFEST_KEY_PREFIX = "COVERCRYPT_KEYSET_MANIFEST_"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class CoverCryptConfigurationError(ValueError):
    """Raised when the active ABAC schema cannot safely form a CoverCrypt authority."""


@dataclass(frozen=True)
class CoverCryptConfiguration:
    """The canonical setup document, its source-schema revision, and fingerprint."""

    dimensions: list[dict[str, Any]]
    attribute_versions: dict[str, int]
    fingerprint: str

    @property
    def config_json(self) -> str:
        return canonical_json({"dimensions": self.dimensions})

    def as_dict(self) -> dict[str, Any]:
        return {
            "config": {"dimensions": self.dimensions},
            "attribute_versions": self.attribute_versions,
            "fingerprint": self.fingerprint,
        }


def canonical_json(value: Any) -> str:
    """Return the byte-stable representation used for JSON and fingerprints."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _validate_identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.isascii() or not _IDENTIFIER_RE.fullmatch(value):
        raise CoverCryptConfigurationError(
            f"{field} contains '{value}', which is not a supported CoverCrypt identifier"
        )


def _validate_values(dimension_name: str, values: Any) -> list[str]:
    if not isinstance(values, list) or not values:
        raise CoverCryptConfigurationError(
            f"AttributeDefinition '{dimension_name}' must have a non-empty allowed_values list"
        )
    if not all(isinstance(value, str) for value in values):
        raise CoverCryptConfigurationError(
            f"AttributeDefinition '{dimension_name}' allowed_values must contain strings only"
        )
    if len(values) != len(set(values)):
        raise CoverCryptConfigurationError(
            f"AttributeDefinition '{dimension_name}' allowed_values must not contain duplicates"
        )
    for value in values:
        _validate_identifier(value, f"AttributeDefinition '{dimension_name}' allowed_values")
    return values


def build_covercrypt_configuration() -> CoverCryptConfiguration:
    """Build the sole ``config_json`` document accepted by CoverCrypt setup.

    Only bounded enum definitions can establish a CoverCrypt dimension. The
    AttributeDefinition model has no hierarchy field, so all generated
    dimensions are non-hierarchical. A future hierarchy requires a reviewed
    schema migration rather than a name-based special case.
    """
    definitions = list(AttributeDefinition.objects.filter(is_active=True, data_type="enum").order_by("name"))
    if not definitions:
        raise CoverCryptConfigurationError("No active enum AttributeDefinition records are available")

    dimensions: list[dict[str, Any]] = []
    attribute_versions: dict[str, int] = {}
    for definition in definitions:
        _validate_identifier(definition.name, "AttributeDefinition name")
        dimensions.append(
            {
                "name": definition.name,
                "attributes": _validate_values(definition.name, definition.allowed_values),
                "hierarchical": False,
            }
        )
        attribute_versions[definition.name] = definition.version

    # user_type is derived from UserProfile rather than UserAttribute, but it
    # appears in the seeded ABAC policies and in CPQA's user context. Model it
    # as a bounded dimension from the active type catalog plus legacy choices.
    user_types = set(UserType.objects.filter(is_active=True).values_list("code", flat=True))
    user_types.update(code for code, _label in UserProfile.USER_TYPE_CHOICES)
    for value in sorted(user_types):
        _validate_identifier(value, "UserType code")
    if user_types:
        dimensions.append({"name": "user_type", "attributes": sorted(user_types), "hierarchical": False})
        attribute_versions["user_type"] = 1
    dimensions.sort(key=lambda dimension: dimension["name"])
    attribute_versions = dict(sorted(attribute_versions.items()))

    fingerprint_payload = {
        "config": {"dimensions": dimensions},
        "attribute_versions": attribute_versions,
    }
    fingerprint = "sha256:" + hashlib.sha256(canonical_json(fingerprint_payload).encode("ascii")).hexdigest()
    return CoverCryptConfiguration(dimensions, attribute_versions, fingerprint)


def manifest_key(keyset_id: str) -> str:
    _validate_identifier(keyset_id, "keyset_id")
    return MANIFEST_KEY_PREFIX + keyset_id


def build_keyset_manifest(
    keyset_id: str,
    vault_mount: str,
    configuration: CoverCryptConfiguration | None = None,
    public_key_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Bind an explicitly named Vault authority to the generated JSON document."""
    _validate_identifier(keyset_id, "keyset_id")
    vault_mount = vault_mount.rstrip("/")
    _validate_identifier(vault_mount, "vault_mount")
    configuration = configuration or build_covercrypt_configuration()
    return {
        "manifest_version": MANIFEST_FORMAT_VERSION,
        "keyset_id": keyset_id,
        "vault_mount": vault_mount,
        "config_fingerprint": configuration.fingerprint,
        "attribute_versions": configuration.attribute_versions,
        "config": {"dimensions": configuration.dimensions},
        "public_key_fingerprint": public_key_fingerprint,
    }


def parse_keyset_manifest(raw_manifest: Any) -> dict[str, Any]:
    """Parse a manifest stored in Vault without accepting ambiguous data."""
    if isinstance(raw_manifest, str):
        try:
            raw_manifest = json.loads(raw_manifest)
        except json.JSONDecodeError as exc:
            raise CoverCryptConfigurationError("Stored CoverCrypt keyset manifest is not valid JSON") from exc
    if not isinstance(raw_manifest, dict):
        raise CoverCryptConfigurationError("Stored CoverCrypt keyset manifest must be an object")
    return raw_manifest


def verify_keyset_manifest(
    raw_manifest: Any,
    keyset_id: str,
    vault_mount: str,
    configuration: CoverCryptConfiguration | None = None,
    public_key_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Fail closed if a named Vault keyset targets another configuration."""
    expected = build_keyset_manifest(keyset_id, vault_mount, configuration, public_key_fingerprint)
    actual = parse_keyset_manifest(raw_manifest)
    required = tuple(expected)
    missing = [field for field in required if field not in actual]
    if missing:
        raise CoverCryptConfigurationError(
            "Stored CoverCrypt keyset manifest is incomplete: " + ", ".join(missing)
        )
    mismatches = [field for field in required if actual[field] != expected[field]]
    if mismatches:
        raise CoverCryptConfigurationError(
            "Stored CoverCrypt keyset manifest is incompatible: " + ", ".join(mismatches)
        )
    return actual
