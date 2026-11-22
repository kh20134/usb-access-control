"""PBKDF2-HMAC-SHA256 password records.

The parameters match the .NET tool (100,000 iterations, 16-byte salt, 32-byte
hash, UTF-8 password bytes) so a hash written by either implementation verifies
in the other. Only the hash is stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from usbac_py.exceptions import AuthorizationError, ValidationError
from usbac_py.models import PasswordRecord, PolicyDocument

ALGORITHM = "PBKDF2-HMAC-SHA256"
ITERATIONS = 100_000
SALT_SIZE = 16
HASH_SIZE = 32
MIN_LENGTH = 8
MAX_LENGTH = 128
_MIN_ITERATIONS = 10_000
_MAX_ITERATIONS = 5_000_000


def validate_plaintext(password: str | None) -> None:
    if password is None or len(password) < MIN_LENGTH:
        raise ValidationError(f"관리자 암호는 {MIN_LENGTH}자 이상이어야 합니다.")
    if len(password) > MAX_LENGTH:
        raise ValidationError(f"관리자 암호는 {MAX_LENGTH}자 이하여야 합니다.")


def create_password(password: str, salt: bytes | None = None) -> PasswordRecord:
    validate_plaintext(password)
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    if len(salt) < 8:
        raise ValidationError("암호 솔트가 너무 짧습니다.")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_SIZE)
    return PasswordRecord(
        algorithm=ALGORITHM,
        iterations=ITERATIONS,
        salt_base64=base64.b64encode(salt).decode("ascii"),
        hash_base64=base64.b64encode(digest).decode("ascii"),
    )


def verify_password(record: PasswordRecord | None, password: str | None) -> bool:
    if record is None or not password:
        return False
    if record.algorithm != ALGORITHM:
        return False
    if record.iterations < _MIN_ITERATIONS or record.iterations > _MAX_ITERATIONS:
        return False
    try:
        salt = base64.b64decode(record.salt_base64, validate=True)
        expected = base64.b64decode(record.hash_base64, validate=True)
    except (ValueError, TypeError):
        return False
    if len(salt) < 8 or not 16 <= len(expected) <= 64:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        record.iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


def ensure_authorized(document: PolicyDocument, password: str | None) -> None:
    if document.admin_password is None:
        return
    if not verify_password(document.admin_password, password):
        raise AuthorizationError("관리자 암호가 올바르지 않습니다.")
