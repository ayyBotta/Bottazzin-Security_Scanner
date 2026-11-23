#!/usr/bin/env python3
"""
Applicazione web locale per lo scanner di sicurezza.

Avvio:
    py app.py              -> apre http://127.0.0.1:8000 nel browser
    py app.py --port 9000  -> porta diversa
    py app.py --no-browser

Il server ascolta solo su 127.0.0.1 (non e' raggiungibile da altri computer).
Espone:
    GET /                      interfaccia web (cartella web/)
    GET /api/scan?domain=...   esegue la scansione e restituisce il JSON
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import webbrowser
from dataclasses import asdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from secscan.report import JsonReporter
from secscan.scanner import DomainUnreachableError, SecurityScanner

WEB_DIR = Path(__file__).resolve().parent / "web"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class ScannerRequestHandler(SimpleHTTPRequestHandler):
    """Serve i file statici di web/ e l'endpoint /api/scan."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/api/scan":
            domain = parse_qs(url.query).get("domain", [""])[0]
            self._handle_scan(domain)
            return
        super().do_GET()

    def _handle_scan(self, raw_domain: str) -> None:
        domain = SecurityScanner.normalize(raw_domain)
        if not DOMAIN_RE.match(domain):
            self._send_json(400, {"error": "Dominio non valido. Esempio: example.com"})
            return
        try:
            result = SecurityScanner().scan(domain)
        except DomainUnreachableError as e:
            lookalike = asdict(e.lookalike) if e.lookalike else None
            self._send_json(502, {"error": str(e), "lookalike": lookalike})
            return
        except Exception as e:  # non far cadere il server per un errore imprevisto
            self._send_json(500, {"error": f"Errore durante la scansione ({e.__class__.__name__})"})
            return
        self._send_json(200, JsonReporter().to_dict(result))

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self) -> None:
        # Lo scanner applica anche a se stesso le buone pratiche che controlla
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Interfaccia web dello scanner di sicurezza")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="non aprire il browser")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), ScannerRequestHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Scanner di sicurezza attivo su {url}  (Ctrl+C per fermare)")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer fermato.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
