"""RS256 JWT signing and verification with JWKS, using the `cryptography` dependency.

This module is deliberately provider-agnostic: the production OIDC client
and the deterministic local test provider share the same signing and
verification code paths, so production validation logic is exercised
unchanged against test key material. No secrets are ever printed.
"""

import base64
import json
import math
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


class JwtValidationError(ValueError):
    """Raised when a JWT or its claims fail structural or cryptographic validation."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding_needed = (-len(segment)) % 4
    try:
        return base64.urlsafe_b64decode(segment + "=" * padding_needed)
    except Exception as exc:
        raise JwtValidationError(f"Malformed base64url segment: {exc}") from exc


def generate_signing_key() -> rsa.RSAPrivateKey:
    """Generate a fresh 2048-bit RSA signing key.

    Production issuers hold keys outside this process. The local test
    provider calls this once per process for its clearly non-secret
    ephemeral key; verification only ever needs the public half.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a private key to unencrypted PKCS#8 PEM (test provider fixtures only)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_jwk(key: rsa.RSAPrivateKey, kid: str) -> Dict[str, Any]:
    """Return the public JWK (with `kid`) for a signing key."""
    pub = key.public_key().public_numbers()
    def _int_to_b64(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return _b64url_encode(n.to_bytes(byte_len, "big"))
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_b64(pub.n),
        "e": _int_to_b64(pub.e),
    }


def sign_jwt(claims: Dict[str, Any], key: rsa.RSAPrivateKey, kid: str) -> str:
    """Sign a JWT with RS256. Header carries only alg, typ, kid."""
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_and_verify_jwt(
    token: str,
    jwks: Dict[str, Any],
    *,
    expected_issuer: str,
    expected_audience: str,
    now_epoch: float,
    leeway_seconds: float = 60.0,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Verify a JWT's signature against the JWKS and validate its envelope claims.

    Returns (header, claims) on success. Envelope validation covers:
      - structural three-segment form,
      - alg == RS256 (rejects alg-confusion / `none` attacks),
      - signature via the JWKS entry selected by `kid`,
      - iss == expected_issuer (exact string match),
      - aud contains expected_audience,
      - exp/iat sanity with a small clock leeway.
    Claim-level policy (role/tenant claims, nonce) belongs to the caller.
    Raises JwtValidationError with a reason code prefix so callers can map
    failures to precise 401 detail without echoing token contents.
    """
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3 or not all(parts):
        raise JwtValidationError("JWT_MALFORMED: token is not a three-segment JWT")

    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JwtValidationError(f"JWT_UNPARSEABLE: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JwtValidationError("JWT_MALFORMED: header and payload must be JSON objects")

    if header.get("alg") != "RS256":
        raise JwtValidationError(f"JWT_ALG_UNSUPPORTED: alg must be RS256, got {header.get('alg')!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise JwtValidationError("JWT_MISSING_KID: signing key id is absent")

    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not keys:
        raise JwtValidationError("JWKS_EMPTY: no signing keys published")
    jwk_entry = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if jwk_entry is None:
        raise JwtValidationError("JWKS_NO_MATCHING_KID: token was signed by an unknown key id")

    try:
        pub_numbers = rsa.RSAPublicNumbers(
            n=int.from_bytes(_b64url_decode(str(jwk_entry["n"])), "big"),
            e=int.from_bytes(_b64url_decode(str(jwk_entry["e"])), "big"),
        )
        public_key = pub_numbers.public_key()
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        public_key.verify(_b64url_decode(signature_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except (KeyError, JwtValidationError, InvalidSignature, ValueError) as exc:
        raise JwtValidationError(f"JWT_SIGNATURE_INVALID: {exc}") from exc

    if claims.get("iss") != expected_issuer:
        raise JwtValidationError("JWT_ISSUER_MISMATCH: token issuer is not the configured issuer")

    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if expected_audience not in aud_list:
        raise JwtValidationError("JWT_AUDIENCE_MISMATCH: token audience does not include this client")

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or not math.isfinite(float(exp)):
        raise JwtValidationError("JWT_EXP_INVALID: exp claim missing or not a number")
    if float(exp) + leeway_seconds < now_epoch:
        raise JwtValidationError("JWT_EXPIRED: token is expired")

    iat = claims.get("iat")
    if iat is not None:
        if not isinstance(iat, (int, float)) or isinstance(iat, bool) or not math.isfinite(float(iat)):
            raise JwtValidationError("JWT_IAT_INVALID: iat claim is not a number")
        if float(iat) - leeway_seconds > now_epoch:
            raise JwtValidationError("JWT_IAT_IN_FUTURE: token issued in the future")

    return header, claims


def claims_without_envelope(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Return the identity/role/tenant claims the session derives from, envelope claims removed."""
    return {k: v for k, v in claims.items() if k not in ("iss", "aud", "exp", "iat", "nbf", "jti")}
