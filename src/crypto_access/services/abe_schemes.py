"""Central ABE scheme registry and backend capability validation."""

from django.conf import settings


SUPPORTED_SCHEMES = ("ac17", "tkn20", "covercrypt")
DEFAULT_SCHEME = "ac17"

BACKEND_SCHEMES = {
    "native": frozenset(("ac17", "tkn20", "covercrypt")),
    "vault": frozenset(("ac17", "tkn20", "covercrypt")),
}


class UnsupportedABEScheme(ValueError):
    """Raised when a scheme/backend pair is unknown or not implemented in CPQA."""


def configured_backend() -> str:
    return "vault" if getattr(settings, "USE_VAULT_ABE_PLUGIN", False) else "native"


def validate_scheme(scheme: str | None = None, *, backend: str | None = None) -> str:
    """Normalize and validate a CPQA scheme before crypto or upload work starts."""
    selected = (scheme if scheme is not None else getattr(settings, "CPABE_SCHEME", DEFAULT_SCHEME))
    if not isinstance(selected, str):
        raise UnsupportedABEScheme("CPABE_SCHEME must be a supported string scheme.")
    selected = selected.strip().lower()
    if selected not in SUPPORTED_SCHEMES:
        raise UnsupportedABEScheme(
            f"Unsupported CP-ABE scheme '{selected}'. Supported schemes: {', '.join(SUPPORTED_SCHEMES)}."
        )

    selected_backend = backend or configured_backend()
    if selected not in BACKEND_SCHEMES.get(selected_backend, frozenset()):
        raise UnsupportedABEScheme(
            f"CP-ABE scheme '{selected}' is not implemented for the '{selected_backend}' backend."
        )
    return selected
