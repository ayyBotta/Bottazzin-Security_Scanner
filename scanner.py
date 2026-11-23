#!/usr/bin/env python3
"""
Security scanner passivo per domini web - punto di ingresso da riga di comando.

Uso:
    py scanner.py example.com
    py scanner.py example.com --json
    py scanner.py --update-tranco      (scarica/aggiorna la classifica dei siti piu' visitati)
"""

import argparse
import json
import sys
from dataclasses import asdict

from secscan.fetcher import HttpFetcher
from secscan.lookalike.tranco import DOWNLOAD_URL, LIST_FILE, TrancoList
from secscan.report import ConsoleReporter, JsonReporter
from secscan.scanner import DomainUnreachableError, SecurityScanner


def main() -> None:
    parser = argparse.ArgumentParser(description="Security scanner passivo per domini web")
    parser.add_argument("domain", nargs="?", help="es. example.com")
    parser.add_argument("--json", action="store_true", help="output in formato JSON")
    parser.add_argument("--update-tranco", action="store_true",
                        help="scarica/aggiorna la classifica Tranco dei siti piu' visitati")
    args = parser.parse_args()

    console = ConsoleReporter()  # configura anche l'output UTF-8 per i domini Unicode
    if args.update_tranco:
        print(f"Scarico la classifica Tranco da {DOWNLOAD_URL} ...")
        info = TrancoList.update(HttpFetcher())
        print(f"Salvati {info['domains']} domini in {LIST_FILE} ({info['downloaded']}).")
        if not args.domain:
            return
    if not args.domain:
        parser.error("indica un dominio, es. py scanner.py example.com")
    try:
        result = SecurityScanner().scan(args.domain)
    except DomainUnreachableError as e:
        if args.json:
            print(json.dumps({"error": str(e), "lookalike": asdict(e.lookalike) if e.lookalike else None},
                             indent=2, ensure_ascii=False))
        else:
            print(f"\n{e}")
            if e.lookalike:
                print("\n".join(console.lookalike_section(e.lookalike)) + "\n")
        sys.exit(1)

    reporter = JsonReporter() if args.json else console
    print(reporter.render(result))


if __name__ == "__main__":
    main()
