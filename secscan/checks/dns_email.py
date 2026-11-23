"""Controlli DNS: SPF, DMARC, CAA."""

from __future__ import annotations

import re

from ..models import Check, ScanContext, Severity, Skip
from .base import BaseChecker

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class DnsChecker(BaseChecker):
    """Protezione da spoofing email (SPF, DMARC) e restrizione delle CA (CAA)."""

    category = "DNS/Email"
    SPECS = {
        "SPF": (4, Severity.MEDIA,
                "Senza SPF (o con ~all/?all) chiunque puo' inviare email che sembrano provenire da questo "
                "dominio, facilitando phishing e truffe a nome dell'organizzazione."),
        "DMARC": (6, Severity.MEDIA,
                  "DMARC indica ai provider di posta cosa fare con le email che falliscono SPF/DKIM: senza "
                  "p=reject o p=quarantine le email contraffatte arrivano comunque nelle caselle delle vittime."),
        "CAA": (2, Severity.BASSA,
                "Senza record CAA qualsiasi autorita' di certificazione puo' emettere certificati per il "
                "dominio, aumentando il rischio di certificati fraudolenti."),
    }

    def _new(self, name: str) -> Check:
        max_points, severity, why = self.SPECS[name]
        return self.check(name, max_points, severity, why)

    def run(self, ctx: ScanContext) -> list[Check]:
        base = ctx.domain.removeprefix("www.")
        if not HAS_DNS:
            checks = [self._new(name) for name in self.SPECS]
            for c in checks:
                c.skip("Manca dnspython (pip install dnspython)", Skip.LOCAL_LIMIT)
            return checks
        return [self._spf(base), self._dmarc(base), self._caa(base)]

    def _txt(self, name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=self.timeout)
            return [b"".join(r.strings).decode(errors="ignore") for r in answers]
        except Exception:
            return []

    def _spf(self, domain: str) -> Check:
        c = self._new("SPF")
        spf = next((t for t in self._txt(domain) if t.lower().startswith("v=spf1")), "")
        if not spf:
            c.message = "Nessun record SPF"
        else:
            c.points = 4 if "-all" in spf else 3 if "~all" in spf else 1
            c.message = spf[:80]
        return c

    def _dmarc(self, domain: str) -> Check:
        c = self._new("DMARC")
        dmarc = next((t for t in self._txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")), "")
        if not dmarc:
            c.message = "Nessun record DMARC"
            return c
        m = re.search(r"\bp\s*=\s*(\w+)", dmarc, re.I)
        policy = m.group(1).lower() if m else "none"
        c.points = {"reject": 6, "quarantine": 5}.get(policy, 2)
        c.message = f"p={policy}"
        return c

    def _caa(self, domain: str) -> Check:
        c = self._new("CAA")
        try:
            dns.resolver.resolve(domain, "CAA", lifetime=self.timeout)
            c.points, c.message = 2, "Presente"
        except Exception:
            c.message = "Nessun record CAA"
        return c
