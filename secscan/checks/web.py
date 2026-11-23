"""Controlli applicativi: cookie, information disclosure, CORS, security.txt."""

from __future__ import annotations

import re

from ..antibot import blocked_message, detect_bot_block, detect_unreliable
from ..fetcher import HttpFetcher
from ..models import Check, ScanContext, Severity, Skip
from .base import BaseChecker


class CookieChecker(BaseChecker):
    """Flag Secure, HttpOnly e SameSite dei cookie della homepage."""

    category = "Cookie"

    def run(self, ctx: ScanContext) -> list[Check]:
        c = self.check("Flag dei cookie", 10, Severity.ALTA,
                       "Senza Secure un cookie puo' viaggiare in chiaro; senza HttpOnly e' leggibile da JavaScript e quindi rubabile con un XSS (furto di sessione); senza SameSite il sito e' esposto a Cross-Site Request Forgery (CSRF).")
        if ctx.bot_block:
            # i cookie della pagina di verifica sono del firewall (es. ak_bmsc), non della sessione del sito
            c.skip(blocked_message(ctx.bot_block), Skip.BOT_BLOCK)
            return [c]
        resp = ctx.own_main_response
        c.source_url = resp.url if resp is not None else None
        cookies = HttpFetcher.raw_set_cookies(resp) if resp is not None else []
        if not cookies:
            c.points, c.message = 10, "Nessun cookie impostato sulla homepage"
            return [c]

        total, ok, problems = 0, 0, []
        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            for flag, present in self._flags(raw.lower()).items():
                total += 1
                if present:
                    ok += 1
                else:
                    problems.append(f"{name}:{flag}")

        c.points = round(10 * ok / total, 1)
        c.message = f"{len(cookies)} cookie" + (
            f"; mancano {', '.join(problems[:6])}" if problems else ", tutti i flag ok"
        )
        return [c]

    @staticmethod
    def _flags(attrs: str) -> dict[str, bool]:
        secure = "; secure" in attrs
        return {
            "Secure": secure,
            "HttpOnly": "; httponly" in attrs,
            "SameSite": "samesite=lax" in attrs or "samesite=strict" in attrs
                        or ("samesite=none" in attrs and secure),
        }


class DisclosureChecker(BaseChecker):
    """Header che rivelano software e versioni del server."""

    category = "Info disclosure"
    TECH_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

    def run(self, ctx: ScanContext) -> list[Check]:
        h = ctx.headers
        checks = [self._server_banner(h), self._tech_headers(h)]
        own = ctx.own_main_response
        for c in checks:
            c.source_url = own.url if own is not None else None
        if ctx.bot_block:
            # banner e header tecnici sono quelli del firewall (es. CloudFront), non del server del sito
            for c in checks:
                c.skip(blocked_message(ctx.bot_block), Skip.BOT_BLOCK)
        return checks

    def _server_banner(self, h) -> Check:
        c = self.check("Banner Server", 5, Severity.BASSA,
                       "Esporre il software del server e la sua versione permette a un attaccante di cercare subito vulnerabilita' note (CVE) specifiche per quella versione, accelerando la ricognizione.")
        server = h.get("Server", "")
        if not server:
            c.points, c.message = 5, "Non esposto"
        elif re.search(r"\d+\.\d+", server):
            c.message = f"Versione esposta: {server}"
        else:
            c.points, c.message = 4, f"Solo nome: {server}"
        return c

    def _tech_headers(self, h) -> Check:
        c = self.check("X-Powered-By / versioni framework", 5, Severity.BASSA,
                       "Rivelare linguaggio e framework (es. PHP, ASP.NET) e le loro versioni indica a un attaccante quali exploit provare, senza alcuno sforzo di ricognizione.")
        leaks = [f"{k}: {h[k]}" for k in self.TECH_HEADERS if k in h]
        if leaks:
            c.message = "; ".join(leaks)
        else:
            c.points, c.message = 5, "Nessuna tecnologia esposta"
        return c


class CorsChecker(BaseChecker):
    """Verifica se il server riflette un Origin arbitrario."""

    category = "CORS"
    TEST_ORIGIN = "https://evil-origin.example"

    def run(self, ctx: ScanContext) -> list[Check]:
        c = self.check("Configurazione CORS", 5, Severity.CRITICA,
                       "Se il server accetta qualsiasi Origin insieme alle credenziali, qualunque sito visitato dall'utente puo' leggere i suoi dati privati su questo dominio sfruttando la sua sessione attiva.")
        if ctx.redirect_target:
            c.skip(f"Rimanda a {ctx.redirect_target}", Skip.REDIRECT)
            return [c]
        r, _ = self.fetcher.best(f"https://{ctx.domain}/", headers={"Origin": self.TEST_ORIGIN})
        if r is None:
            c.skip("Nessuna risposta alla richiesta di prova", Skip.REQUEST_FAILED)
            return [c]
        c.source_url = r.url
        blocked = detect_unreliable(r)
        if blocked:
            c.skip(blocked_message(blocked), Skip.BOT_BLOCK)
            return [c]

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == self.TEST_ORIGIN and creds:
            c.message = "Origin arbitrario riflesso CON credenziali (grave)"
        elif acao == self.TEST_ORIGIN:
            c.points, c.message = 2, "Origin arbitrario riflesso (senza credenziali)"
            c.severity = Severity.MEDIA
            c.why = ("Il server autorizza qualsiasi sito a leggere le sue risposte: non vengono esposti dati di sessione, "
                     "ma eventuali informazioni non pubbliche accessibili senza login diventano leggibili da siti terzi.")
        elif acao == "*":
            c.points, c.message = 4, "Wildcard * (ok per risorse pubbliche)"
        else:
            c.points, c.message = 5, "Nessuna apertura cross-origin"
        return [c]


class SecurityTxtChecker(BaseChecker):
    """Presenza di /.well-known/security.txt (RFC 9116)."""

    category = "Varie"

    def run(self, ctx: ScanContext) -> list[Check]:
        c = self.check("security.txt", 3, Severity.INFO,
                       "Senza security.txt chi scopre una vulnerabilita' non sa a chi segnalarla: le segnalazioni si perdono e le falle restano aperte piu' a lungo.")
        if ctx.redirect_target:
            c.skip(f"Rimanda a {ctx.redirect_target}", Skip.REDIRECT)
            return [c]
        # il certificato e' gia' giudicato da TlsChecker: qui conta solo il contenuto del file
        r, _ = self.fetcher.best(f"https://{ctx.domain}/.well-known/security.txt")
        blocked = detect_bot_block(r)
        c.source_url = r.url if r is not None else None
        if r is not None and r.status_code == 200 and "contact:" in r.text.lower():
            c.points, c.message = 3, "Presente"
        elif blocked:
            c.skip(blocked_message(blocked), Skip.BOT_BLOCK)
        else:
            c.message = "Assente"
        return [c]
