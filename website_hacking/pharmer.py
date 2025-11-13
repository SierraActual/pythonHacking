#!/usr/bin/env python3
"""
Run with: sudo python3 server.py
Serves HTTP on :80 and HTTPS on :443. GET / and /login serve index.html.
Logs POST params for any POST request to the console.
"""
import os
import ssl
import urllib.parse
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import subprocess
import sys

# Ensure Python 3
if sys.version_info[0] < 3:
    print("ERROR: This script requires Python 3. Run with: sudo python3 server.py")
    sys.exit(1)

INDEX_FILE = "index.html"
CERT_FILE = "server.crt"
KEY_FILE = "server.key"
HTTP_PORT = 80
HTTPS_PORT = 443

class LoggingHandler(SimpleHTTPRequestHandler):
    # ensure we serve files from cwd
    def do_GET(self):
        # Normalize path (strip query)
        path = self.path.split('?', 1)[0]
        if path in ("/", "/login", "/login/"):
            idx = Path(os.getcwd()) / INDEX_FILE
            if idx.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                data = idx.read_bytes()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            else:
                # f-string is fine in py3
                self.send_error(404, f"{INDEX_FILE} not found")
                return
        # Otherwise fallback to normal static file behavior
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length > 0 else b''
        content_type = (self.headers.get('Content-Type') or '').lower()

        parsed = {}
        if 'application/x-www-form-urlencoded' in content_type:
            parsed = urllib.parse.parse_qs(raw.decode('utf-8', errors='replace'))
        elif 'multipart/form-data' in content_type:
            # don't fully parse multipart here; show a short raw preview
            parsed = {'_multipart_preview': [raw.decode('utf-8', errors='replace')[:200]]}
        else:
            parsed = {'_raw': [raw.decode('utf-8', errors='replace')]}

        # Log
        print("\n--- POST received ---")
        print(f"Host: {self.headers.get('Host')}")
        print(f"Path: {self.path}")
        print("Params:")
        for k, v in parsed.items():
            print(f"  {k}: {v}")
        print("---------------------\n")

        # Reply (use unicode string encoded to utf-8 instead of a b"...")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<h3>POST received — check server log.</h3>".encode('utf-8'))

def ensure_cert():
    # Generate self-signed cert if missing
    if Path(CERT_FILE).exists() and Path(KEY_FILE).exists():
        return
    print("Cert/key not found — generating self-signed certificate (server.crt/server.key)...")
    cmd = [
        "openssl", "req", "-new", "-x509",
        "-days", "365",
        "-nodes",
        "-subj", "/CN=login.brightsheepproblems.org",
        "-keyout", KEY_FILE,
        "-out", CERT_FILE
    ]
    try:
        subprocess.check_call(cmd)
    except Exception as e:
        print("Failed to auto-generate cert with openssl. Please create server.crt & server.key manually.")
        raise

def run_http_server():
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), LoggingHandler)
    print(f"HTTP :{HTTP_PORT} -> serving files from {os.getcwd()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

def run_https_server():
    ensure_cert()
    server = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), LoggingHandler)
    # Wrap socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"HTTPS :{HTTPS_PORT} -> serving files from {os.getcwd()} (self-signed cert)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: Binding to ports 80/443 requires root. Run with sudo to bind privileged ports.")
    # Start both servers in threads
    t_http = threading.Thread(target=run_http_server, daemon=True)
    t_https = threading.Thread(target=run_https_server, daemon=True)
    t_http.start()
    t_https.start()
    print("Servers started. Press Ctrl+C to stop.")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)
