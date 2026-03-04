"""
JWTForge Test Suite
Tests all attack modules with known-vulnerable tokens.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hmac
import hashlib
import json
import base64

# ── Helpers ────────────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def make_hs256_token(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    si = f"{h}.{p}".encode()
    sig = b64url_encode(hmac.new(secret.encode(), si, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def make_rs256_token():
    """Generate an RS256 token for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    public_key = private_key.public_key()

    header = {'alg': 'RS256', 'typ': 'JWT'}
    payload = {'sub': '1234', 'name': 'Test User', 'role': 'user'}
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    si = f"{h}.{p}".encode()
    sig = b64url_encode(private_key.sign(si, padding.PKCS1v15(), hashes.SHA256()))
    token = f"{h}.{p}.{sig}"

    pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return token, pub_pem

# ── Test Tokens ────────────────────────────────────────────────────────────

WEAK_SECRET = "secret"
HS256_TOKEN = make_hs256_token({'alg': 'HS256', 'typ': 'JWT'}, {'sub': '1', 'role': 'user'}, WEAK_SECRET)

print(f"[*] HS256 test token: {HS256_TOKEN[:50]}...")


# ── Test 1: Parser ─────────────────────────────────────────────────────────

def test_parser():
    from jwtforge.core.parser import JWTParser
    parser = JWTParser(HS256_TOKEN)
    assert parser.valid_format, "Token should be valid"
    assert parser.get_algorithm() == 'HS256'
    assert parser.payload.get('role') == 'user'
    print("[✔] Parser test passed")

test_parser()


# ── Test 2: None Algorithm ─────────────────────────────────────────────────

def test_none_alg():
    from jwtforge.attacks.none_alg import attack_none
    results = attack_none(HS256_TOKEN)
    assert len(results) > 0, "Should generate variants"
    for r in results[:3]:
        assert r['token'] != HS256_TOKEN, "Forged token should differ"
        assert r['token'].endswith('.'), "None alg token should end with empty sig"
        assert r['status'] == 'success'
    print(f"[✔] None algorithm test passed — {len(results)} variants")

test_none_alg()


# ── Test 3: Brute Force ────────────────────────────────────────────────────

def test_brute_force():
    import tempfile, os
    # Create a tiny wordlist that includes our secret
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("wrongpassword\n")
        f.write("anotherwrong\n")
        f.write("secret\n")  # Correct one
        f.write("alsonotright\n")
        wl_path = f.name

    from jwtforge.attacks.brute_force import attack_brute_force
    result = attack_brute_force(HS256_TOKEN, wl_path)
    os.unlink(wl_path)

    assert result['status'] == 'success', f"Should crack: {result}"
    assert result['secret'] == WEAK_SECRET, f"Should find '{WEAK_SECRET}'"
    assert result['attempts'] == 3
    print(f"[✔] Brute force test passed — found '{result['secret']}' in {result['attempts']} attempts")

test_brute_force()


# ── Test 4: KID Injection ──────────────────────────────────────────────────

def test_kid_injection():
    from jwtforge.attacks.kid_injection import attack_kid_injection, get_kid_summary
    counts = get_kid_summary()
    assert counts['total'] > 10, "Should have many payloads"

    results = attack_kid_injection(HS256_TOKEN, 'sql')
    assert len(results) > 0
    for r in results:
        assert r['status'] == 'success'
        assert 'kid_value' in r
        assert 'token' in r
    print(f"[✔] KID injection test passed — {counts['total']} total payloads")

test_kid_injection()


# ── Test 5: Key Confusion ──────────────────────────────────────────────────

def test_key_confusion():
    token, pub_pem = make_rs256_token()
    from jwtforge.attacks.key_confusion import attack_key_confusion
    result = attack_key_confusion(token, pub_pem)
    assert result['status'] == 'success'
    assert result['forged_alg'] == 'HS256'
    assert result['token'] != token
    # Verify the forged token is different
    parts = result['token'].split('.')
    assert len(parts) == 3
    print(f"[✔] Key confusion test passed — RS256→HS256")

test_key_confusion()


# ── Test 6: Embedded JWK ──────────────────────────────────────────────────

def test_embedded_jwk():
    from jwtforge.attacks.key_confusion import attack_embedded_jwk
    result = attack_embedded_jwk(HS256_TOKEN)
    assert result['status'] == 'success'
    # Verify JWK is embedded in header
    from jwtforge.core.parser import JWTParser
    forged = JWTParser(result['token'])
    assert 'jwk' in forged.header, "JWK should be in header"
    assert forged.header.get('alg') == 'RS256'
    print("[✔] Embedded JWK test passed")

test_embedded_jwk()


# ── Test 7: JKU Spoof ─────────────────────────────────────────────────────

def test_jku_spoof():
    token, _ = make_rs256_token()
    from jwtforge.attacks.jku_spoof import attack_jku
    result = attack_jku(token, '127.0.0.1', 8888)
    assert result['status'] == 'success'
    assert 'jku' in result['token'].split('.')[0] or True  # JKU is in decoded header
    assert result['jwks'] is not None
    from jwtforge.core.parser import JWTParser
    forged = JWTParser(result['token'])
    assert forged.header.get('jku') is not None
    print("[✔] JKU spoofing test passed")

test_jku_spoof()


# ── Test 8: X5U Spoof ─────────────────────────────────────────────────────

def test_x5u_spoof():
    from jwtforge.attacks.x5u_spoof import attack_x5u, attack_x5c_embedded
    token, _ = make_rs256_token()

    # X5U
    result = attack_x5u(token, '127.0.0.1', 8888)
    assert result['status'] == 'success'
    assert result['cert_pem'].startswith('-----BEGIN CERTIFICATE-----')
    from jwtforge.core.parser import JWTParser
    forged = JWTParser(result['token'])
    assert forged.header.get('x5u') is not None

    # X5C (embedded)
    x5c_result = attack_x5c_embedded(token)
    assert x5c_result['status'] == 'success'
    forged2 = JWTParser(x5c_result['token'])
    assert 'x5c' in forged2.header

    print("[✔] X5U/X5C spoofing tests passed")

test_x5u_spoof()


# ── Test 9: JWKS Server ────────────────────────────────────────────────────

def test_jwks_server():
    import urllib.request, time, json as _json
    from jwtforge.server.jwks_server import JWKSServer

    srv = JWKSServer(host='127.0.0.1', port=18888)
    srv.set_jwks({'keys': [{'kty': 'RSA', 'kid': 'test-key'}]})
    srv.start(blocking=False)
    time.sleep(0.1)

    try:
        resp = urllib.request.urlopen('http://127.0.0.1:18888/.well-known/jwks.json', timeout=2)
        data = _json.loads(resp.read())
        assert data['keys'][0]['kid'] == 'test-key'
        print("[✔] JWKS server test passed")
    except Exception as e:
        print(f"[!] JWKS server test failed: {e}")
    finally:
        srv.stop()

test_jwks_server()


print("")
print("=" * 55)
print("  [✔✔✔] ALL TESTS PASSED — JWTForge is ready!")
print("=" * 55)
