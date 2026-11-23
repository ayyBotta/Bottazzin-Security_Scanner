"""Controlli sugli header di sicurezza HTTP."""

from __future__ import annotations

import re

from ..antibot import blocked_message
from ..models import Check, ScanContext, Severity, Skip
from .base import BaseChecker


class CspAnalyzer:
    """Valuta la robustezza di una Content-Security-Policy."""

    MAX_POINTS = 10
    HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
    WILDCARDS = ("*", "http:", "https:", "data:")

    def __init__(self, policy: str):
        self.policy = policy
        self.directives = self._parse(policy)

    @staticmethod
    def _parse(policy: str) -> dict[str, list[str]]:
        directives = {}
        for part in policy.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
        return directives

    def has_frame_ancestors(self) -> bool:
        return "frame-ancestors" in self.directives

    # punteggi dei casi (su MAX_POINTS = 10)
    POINTS_ABSENT = 0
    POINTS_REPORT_ONLY = 1      # il browser segnala ma non blocca
    POINTS_NO_XSS = 3           # presente, ma non ferma gli script iniettati
    POINTS_NO_OBJECT_SRC = 9    # protegge dagli XSS, manca solo object-src

    def xss_weaknesses(self) -> list[str]:
        """Motivi per cui la policy NON protegge dagli XSS (lista vuota = protegge)."""
        d = self.directives
        script = d.get("script-src", d.get("default-src"))
        if script is None:
            present = ", ".join(d) or "nessuna direttiva"
            return [f"manca script-src/default-src (contiene solo: {present})"]
        issues = []
        has_nonce_or_hash = any(t.startswith(self.HASH_PREFIXES) for t in script)
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            issues.append("'unsafe-inline'")  # con nonce/hash i browser moderni lo ignorano
        if "'unsafe-eval'" in script:
            issues.append("'unsafe-eval'")
        if any(t in self.WILDCARDS for t in script):
            issues.append("sorgenti wildcard")
        return issues

    def score(self) -> tuple[int, str]:
        """Punteggio di una policy APPLICATA (non report-only)."""
        weak = self.xss_weaknesses()
        if weak:
            return self.POINTS_NO_XSS, "Presente ma non protegge dagli XSS: " + ", ".join(weak)
        d = self.directives
        if "object-src" not in d and "'none'" not in d.get("default-src", []):
            return self.POINTS_NO_OBJECT_SRC, "Protegge dagli XSS (manca solo object-src)"
        return self.MAX_POINTS, "Protegge dagli XSS"


class HeadersChecker(BaseChecker):
    """HSTS, CSP, clickjacking, nosniff, Referrer-Policy, Permissions-Policy."""

    category = "Header"
    HSTS_MIN_AGE = 15552000  # 180 giorni
    GOOD_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    OK_REFERRER = {"origin", "origin-when-cross-origin"}

    def run(self, ctx: ScanContext) -> list[Check]:
        h = ctx.headers
        own = ctx.own_main_response
        csp = CspAnalyzer(h.get("Content-Security-Policy", ""))
        hsts, *hsts_redirects = self._hsts(ctx)
        content = [
            self._csp(h, csp),
            self._clickjacking(h, csp),
            self._nosniff(h),
            self._referrer(h),
            self._permissions(h),
        ]
        for c in content:
            c.source_url = own.url if own is not None else None
        if ctx.redirect_target:
            # un dominio di solo redirect (risposta 3xx senza contenuto) non mostra pagine: gli header sui
            # contenuti non lo riguardano. Resta HSTS, che protegge proprio il passaggio dal redirect.
            for c in content:
                c.skip(f"Rimanda a {ctx.redirect_target}", Skip.REDIRECT)
        elif ctx.bot_block:
            # header della pagina di blocco, non del sito. HSTS, se presente, vale comunque
            # (il browser lo applica a tutto l'host): si esclude solo quando manca.
            for c in content if hsts.points else [hsts, *content]:
                c.skip(blocked_message(ctx.bot_block), Skip.BOT_BLOCK)
        return [hsts, *hsts_redirects, *content]

    def _hsts(self, ctx: ScanContext) -> list[Check]:
        """HSTS sulla risposta finale del dominio e, a parte, sui redirect HTTPS intermedi dello stesso
        dominio (es. https://google.com -> https://www.google.com)."""
        c = self.check("Strict-Transport-Security", 8, Severity.ALTA,
                       "Senza HSTS il browser puo' essere indotto a collegarsi in HTTP (alla prima visita o tramite un link manipolato), permettendo un attacco SSL stripping anche se il sito supporta HTTPS.")
        hops = ctx.own_https_hops
        final = hops[-1] if hops else None
        c.source_url = final.url if final is not None else None
        hsts = final.headers.get("Strict-Transport-Security", "") if final is not None else ""
        if not hsts:
            c.message = "Assente"
        else:
            c.points, c.message = self._hsts_points(hsts), hsts
        checks = [c]

        intermediate = hops[:-1]
        if intermediate:
            r = self.check("HSTS sul redirect iniziale", 2, Severity.BASSA,
                           "Il redirect iniziale (es. https://dominio.it -> https://www.dominio.it) e' il primo "
                           "contatto di chi digita l'indirizzo: se non manda HSTS, il browser non memorizza la "
                           "protezione per il dominio principale e la prossima visita via http:// resta esposta "
                           "a SSL stripping. Rischio minore che sulla pagina finale, ma reale.")
            missing = [h.url for h in intermediate if not h.headers.get("Strict-Transport-Security")]
            if missing:
                r.source_url = missing[0]
                r.message = "Assente su " + ", ".join(missing)
            else:
                r.source_url = intermediate[0].url
                r.points, r.message = 2, "Presente anche sui redirect intermedi"
            checks.append(r)
        return checks

    def _hsts_points(self, hsts: str) -> int:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        max_age = int(m.group(1)) if m else 0
        points = 6 if max_age >= self.HSTS_MIN_AGE else 3 if max_age > 0 else 0
        if points and "includesubdomains" in hsts.lower():
            points += 1
        if points and "preload" in hsts.lower():
            points += 1
        return points

    def _csp(self, h, csp: CspAnalyzer) -> Check:
        c = self.check("Content-Security-Policy", CspAnalyzer.MAX_POINTS, Severity.ALTA,
                       "La CSP e' la principale difesa del browser contro il Cross-Site Scripting (XSS): senza di essa, o con 'unsafe-inline', 'unsafe-eval' o sorgenti wildcard, uno script iniettato puo' rubare sessioni, dati e credenziali degli utenti.")
        if csp.policy:
            c.points, c.message = csp.score()
        elif h.get("Content-Security-Policy-Report-Only"):
            c.points = CspAnalyzer.POINTS_REPORT_ONLY
            c.message = "Solo Report-Only: il browser segnala le violazioni ma non le blocca"
        else:
            c.points, c.message = CspAnalyzer.POINTS_ABSENT, "Assente"
        return c

    def _clickjacking(self, h, csp: CspAnalyzer) -> Check:
        c = self.check("Protezione clickjacking", 6, Severity.MEDIA,
                       "Il sito puo' essere caricato in un iframe invisibile dentro una pagina malevola, inducendo l'utente a cliccare inconsapevolmente su pulsanti reali (clickjacking), ad esempio per confermare pagamenti o cambiare impostazioni.")
        xfo = h.get("X-Frame-Options", "").upper()
        if csp.has_frame_ancestors():
            c.points, c.message = 6, "CSP frame-ancestors"
        elif xfo in ("DENY", "SAMEORIGIN"):
            c.points, c.message = 6, f"X-Frame-Options: {xfo}"
        else:
            c.message = "Ne' X-Frame-Options ne' frame-ancestors"
        return c

    def _nosniff(self, h) -> Check:
        c = self.check("X-Content-Type-Options", 6, Severity.BASSA,
                       "Senza nosniff il browser puo' 'indovinare' il tipo di un file e interpretare come script contenuti caricati dagli utenti, facilitando attacchi XSS.")
        if h.get("X-Content-Type-Options", "").strip().lower() == "nosniff":
            c.points, c.message = 6, "nosniff"
        else:
            c.message = "Assente o diverso da nosniff"
        return c

    def _referrer(self, h) -> Check:
        c = self.check("Referrer-Policy", 5, Severity.BASSA,
                       "Una policy permissiva invia a siti terzi l'URL completo della pagina di provenienza, che puo' contenere token, identificativi di sessione o dati personali.")
        rp = h.get("Referrer-Policy", "").lower()
        if not rp:
            c.points, c.message = 2, "Assente (i browser moderni usano un default sicuro)"
            return c
        last = rp.split(",")[-1].strip()  # il browser usa l'ultimo valore valido
        c.points = 5 if last in self.GOOD_REFERRER else 3 if last in self.OK_REFERRER else 1
        c.message = rp
        return c

    def _permissions(self, h) -> Check:
        c = self.check("Permissions-Policy", 5, Severity.BASSA,
                       "Senza Permissions-Policy script di terze parti o iframe incorporati possono chiedere accesso a fotocamera, microfono, geolocalizzazione e altre API sensibili del browser.")
        if h.get("Permissions-Policy"):
            c.points, c.message = 5, "Presente"
        elif h.get("Feature-Policy"):
            c.points, c.message = 2, "Solo Feature-Policy (deprecato)"
        else:
            c.message = "Assente"
        return c
