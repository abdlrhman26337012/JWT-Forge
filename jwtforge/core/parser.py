"""
JWTForge - Core JWT Parser
Handles decoding, encoding, and manipulation of JWT tokens.
"""

import base64
import json
import re
from typing import Optional, Dict, Any, Tuple, List


def b64url_decode(data: str) -> bytes:
    """Decode base64url string with automatic padding."""
    data = data.strip()
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)


def b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def build_signing_input(header: Dict, payload: Dict) -> bytes:
    """Build the signing input (header.payload) as bytes."""
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    return f"{h}.{p}".encode()


def build_signing_input_raw(header_b64: str, payload_b64: str) -> bytes:
    """Build signing input from raw base64url parts."""
    return f"{header_b64}.{payload_b64}".encode()


class JWTParser:
    """Parse and manipulate JWT tokens."""

    def __init__(self, token: str):
        self.raw_token = token.strip()
        self.parts: List[str] = self.raw_token.split('.')
        self.valid_format: bool = len(self.parts) >= 2

        self.header_b64: str = self.parts[0] if len(self.parts) > 0 else ''
        self.payload_b64: str = self.parts[1] if len(self.parts) > 1 else ''
        self.signature_b64: str = self.parts[2] if len(self.parts) > 2 else ''

        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature_bytes: bytes = b''

        self._parse()

    def _parse(self):
        try:
            self.header = json.loads(b64url_decode(self.header_b64))
        except Exception:
            self.header = {}

        try:
            self.payload = json.loads(b64url_decode(self.payload_b64))
        except Exception:
            self.payload = {}

        try:
            if self.signature_b64:
                self.signature_bytes = b64url_decode(self.signature_b64)
        except Exception:
            self.signature_bytes = b''

    def get_algorithm(self) -> str:
        return self.header.get('alg', 'unknown')

    def get_kid(self) -> Optional[str]:
        return self.header.get('kid')

    def get_jku(self) -> Optional[str]:
        return self.header.get('jku')

    def get_x5u(self) -> Optional[str]:
        return self.header.get('x5u')

    def is_symmetric(self) -> bool:
        alg = self.get_algorithm().upper()
        return alg.startswith('HS')

    def is_asymmetric(self) -> bool:
        alg = self.get_algorithm().upper()
        return alg.startswith('RS') or alg.startswith('ES') or alg.startswith('PS')

    def forge(self, new_header: Dict, new_payload: Dict, new_signature: str = '') -> str:
        """Build a new JWT with given header, payload, and signature (base64url string)."""
        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        return f"{h}.{p}.{new_signature}"

    def forge_with_sig_bytes(self, new_header: Dict, new_payload: Dict, sig: bytes) -> str:
        """Build a new JWT with binary signature."""
        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        s = b64url_encode(sig)
        return f"{h}.{p}.{s}"

    def get_signing_input(self) -> bytes:
        """Return the original signing input bytes."""
        return f"{self.header_b64}.{self.payload_b64}".encode()

    def describe(self) -> Dict[str, Any]:
        """Return a description dict for reporting."""
        import time
        now = int(time.time())
        exp = self.payload.get('exp')
        iat = self.payload.get('iat')
        nbf = self.payload.get('nbf')

        return {
            'algorithm': self.get_algorithm(),
            'header': self.header,
            'payload': self.payload,
            'kid': self.get_kid(),
            'jku': self.get_jku(),
            'x5u': self.get_x5u(),
            'has_signature': bool(self.signature_b64),
            'is_expired': (exp is not None and exp < now),
            'expiry': exp,
            'issued_at': iat,
            'not_before': nbf,
            'subject': self.payload.get('sub'),
            'issuer': self.payload.get('iss'),
            'audience': self.payload.get('aud'),
        }
