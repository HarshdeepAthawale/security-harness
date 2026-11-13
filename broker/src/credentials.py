from __future__ import annotations
import os
import re


class CredentialError(RuntimeError):
    pass


def get_credential(identity: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity):
        raise CredentialError("credential_missing")
    value = os.environ.get("BROKER_SECRET_" + identity.upper().replace("-", "_"))
    if not value:
        raise CredentialError("credential_missing")
    return value