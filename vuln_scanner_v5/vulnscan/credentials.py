"""Secure local storage for the user's NVD API key.

Uses the operating system credential vault through keyring. Environment-variable
fallback is supported for headless/CI deployments. Secrets are never written to
project files or logs.
"""
import os

SERVICE_NAME = "VulnWatch"
ACCOUNT_NAME = "NVD_API_KEY"


def get_nvd_api_key() -> str:
    try:
        import keyring  # type: ignore
        value = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
        if value:
            return value
    except Exception:
        pass
    return os.environ.get("NVD_API_KEY", "")


def set_nvd_api_key(value: str) -> None:
    value = (value or "").strip()
    if not value:
        raise ValueError("API key cannot be empty")
    try:
        import keyring  # type: ignore
        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, value)
    except Exception as exc:
        raise RuntimeError(
            "Could not save the key in the operating-system credential vault. "
            "Install the 'keyring' package and configure a system keyring."
        ) from exc
