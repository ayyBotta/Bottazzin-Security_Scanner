"""Data di registrazione del dominio tramite RDAP, con WHOIS come riserva."""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

import requests

from ..fetcher import HttpFetcher


class DomainAgeLookup:
    RDAP_URL = "https://rdap.org/domain/{}"
    IANA_WHOIS = "whois.iana.org"
    CREATED_RE = re.compile(
        r"^\s*(?:creation date|created(?: on)?|registered(?: on)?|registration (?:time|date)"
        r"|domain registration date)\s*:\s*(\d{4}-\d{2}-\d{2})",
        re.I | re.M,
    )

    def __init__(self, fetcher: HttpFetcher):
        self.fetcher = fetcher
        self.timeout = fetcher.timeout

    def lookup(self, registrable: str) -> tuple[str | None, int | None, str | None]:
        """Restituisce (data di registrazione ISO, eta' in giorni, fonte) oppure (None, None, None)."""
        created, source = self._rdap(registrable), "RDAP"
        if created is None:
            created, source = self._whois(registrable), "WHOIS"
        if created is None:
            return None, None, None
        days = (datetime.now(timezone.utc) - created).days
        return created.date().isoformat(), days, source

    # --- RDAP ------------------------------------------------------------- #
    def _rdap(self, domain: str) -> datetime | None:
        try:
            r = self.fetcher.get(self.RDAP_URL.format(domain), headers={"Accept": "application/rdap+json"})
            if r.status_code != 200:
                return None
            events = r.json().get("events", [])
        except (requests.RequestException, ValueError):
            return None
        for event in events:
            if event.get("eventAction") == "registration":
                return self._parse(event.get("eventDate", ""))
        return None

    # --- WHOIS ------------------------------------------------------------ #
    def _whois(self, domain: str) -> datetime | None:
        tld = domain.rsplit(".", 1)[-1]
        iana = self._query(self.IANA_WHOIS, tld) or ""
        server = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.I | re.M)
        if not server:
            return None
        answer = self._query(server.group(1), domain) or ""
        match = self.CREATED_RE.search(answer)
        return self._parse(match.group(1)) if match else None

    def _query(self, server: str, query: str) -> str | None:
        try:
            with socket.create_connection((server, 43), timeout=self.timeout) as sock:
                sock.sendall(f"{query}\r\n".encode())
                chunks = []
                while data := sock.recv(4096):
                    chunks.append(data)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except OSError:
            return None

    @staticmethod
    def _parse(value: str) -> datetime | None:
        value = value.strip()
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = datetime.strptime(value[:10], "%Y-%m-%d")
            except ValueError:
                return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
