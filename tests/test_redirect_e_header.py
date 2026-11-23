"""Test senza rete: redirect, header, CSP, blocchi anti-bot, TLS legacy.

Eseguire dalla cartella del progetto:  py -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secscan.antibot import detect_bot_block, detect_unreliable  # noqa: E402
from secscan.checks.headers import CspAnalyzer, HeadersChecker  # noqa: E402
from secscan.checks.tls import HttpsChecker, TlsChecker  # noqa: E402
from secscan.fetcher import HttpFetcher  # noqa: E402
from secscan.models import ScanContext, Severity, Skip  # noqa: E402

HSTS = "max-age=157680000; includeSubDomains; preload"
CONTENT_HEADERS = ("Content-Security-Policy", "Protezione clickjacking", "X-Content-Type-Options",
                   "Referrer-Policy", "Permissions-Policy")


def fake(url: str, status: int = 200, headers: dict | None = None, body: str = "") -> requests.Response:
    r = requests.Response()
    r.url, r.status_code = url, status
    r.headers = CaseInsensitiveDict(headers or {})
    r._content = body.encode()
    r.encoding = "utf-8"
    return r


def chain(*hops: requests.Response) -> requests.Response:
    """Ultima risposta con le precedenti in history, come fa requests seguendo i redirect."""
    final = hops[-1]
    final.history = list(hops[:-1])
    return final


def redirect(url: str, to: str, status: int = 302, headers: dict | None = None) -> requests.Response:
    return fake(url, status, {"Location": to, "Content-Length": "0", **(headers or {})})


def by_name(checks):
    return {c.name: c for c in checks}


class TestRedirectStessoDominio(unittest.TestCase):
    """302 senza header seguito da un 200 con header, sullo stesso dominio (example.com -> www)."""

    def setUp(self):
        self.ctx = ScanContext(domain="example.com")
        self.ctx.https_response = chain(
            redirect("https://example.com/", "https://www.example.com/"),
            fake("https://www.example.com/", 200, {
                "Strict-Transport-Security": HSTS,
                "Content-Security-Policy": "default-src 'self'; object-src 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            }, "<html><title>Example</title></html>"))
        self.checks = by_name(HeadersChecker(HttpFetcher()).run(self.ctx))

    def test_header_letti_sulla_risposta_finale(self):
        self.assertEqual(self.ctx.redirect_target, None)
        for name in ("Strict-Transport-Security", "Content-Security-Policy",
                     "Protezione clickjacking", "X-Content-Type-Options"):
            c = self.checks[name]
            self.assertFalse(c.skipped, name)
            self.assertEqual(c.points, c.max_points, name)
            self.assertEqual(c.source_url, "https://www.example.com/", name)

    def test_hsts_mancante_sul_redirect_apex_segnalato_a_parte(self):
        c = self.checks["HSTS sul redirect iniziale"]
        self.assertEqual(c.points, 0)
        self.assertEqual(c.source_url, "https://example.com/")
        self.assertEqual(c.severity, Severity.BASSA)  # meno grave dell'HSTS finale (ALTA)
        self.assertEqual(self.checks["Strict-Transport-Security"].severity, Severity.ALTA)


class TestDominioDiSoloRedirect(unittest.TestCase):
    """zalando.com: 302 vuoto (CloudFront) verso un altro dominio (www.zalando.it)."""

    def setUp(self):
        self.ctx = ScanContext(domain="zalando.com")
        self.ctx.https_response = chain(
            redirect("https://zalando.com/", "https://www.zalando.it/", headers={"Server": "CloudFront"}),
            fake("https://www.zalando.it/", 200, {
                "Strict-Transport-Security": "max-age=157680000",
                "Content-Security-Policy": "frame-ancestors 'self'",
                "X-Frame-Options": "sameorigin",
            }))
        self.ctx.http_response = chain(
            redirect("http://zalando.com/", "https://zalando.com/", 301),
            redirect("https://zalando.com/", "https://www.zalando.it/"),
            fake("https://www.zalando.it/", 200))

    def test_nessuna_penalita_per_csp_e_clickjacking(self):
        checks = by_name(HeadersChecker(HttpFetcher()).run(self.ctx))
        self.assertEqual(self.ctx.redirect_target, "www.zalando.it")
        for name in CONTENT_HEADERS:
            self.assertTrue(checks[name].skipped, name)
            self.assertIs(checks[name].skip_reason, Skip.REDIRECT, name)
            self.assertFalse(checks[name].is_finding, name)
        # HSTS resta valutato, sulla risposta di redirect del dominio stesso
        hsts = checks["Strict-Transport-Security"]
        self.assertFalse(hsts.skipped)
        self.assertEqual(hsts.source_url, "https://zalando.com/")
        self.assertNotIn("HSTS sul redirect iniziale", checks)

    def test_penalita_per_tls_legacy_sul_redirect(self):
        tls = TlsChecker(HttpFetcher())
        accepted = {"zalando.com": ["TLSv1", "TLSv1.1"], "www.zalando.it": []}
        with mock.patch.object(TlsChecker, "_probe_legacy", lambda self, host: accepted[host]):
            checks = tls._legacy_protocols(self.ctx)
        self.assertEqual(len(checks), 1)  # l'host finale (www.zalando.it) e' un altro sito: scansione a parte
        c = checks[0]
        self.assertEqual(c.points, 0)
        self.assertTrue(c.is_finding)
        self.assertIn("zalando.com", c.message)

    def test_primo_salto_http_va_subito_su_https(self):
        c = HttpsChecker(HttpFetcher())._http_redirect(self.ctx)
        self.assertEqual(c.points, c.max_points)


class TestCsp(unittest.TestCase):
    def test_solo_frame_ancestors_e_csp_parziale(self):
        points, message = CspAnalyzer("frame-ancestors 'self' https://*.zalando.it").score()
        self.assertEqual(points, CspAnalyzer.POINTS_NO_XSS)
        self.assertIn("non protegge dagli XSS", message)
        self.assertIn("frame-ancestors", message)

    def test_frame_ancestors_vale_come_protezione_clickjacking(self):
        ctx = ScanContext(domain="example.com")
        ctx.https_response = fake("https://example.com/", 200, {"Content-Security-Policy": "frame-ancestors 'self'"})
        checks = by_name(HeadersChecker(HttpFetcher()).run(ctx))
        self.assertEqual(checks["Protezione clickjacking"].points, 6)
        self.assertEqual(checks["Content-Security-Policy"].points, CspAnalyzer.POINTS_NO_XSS)

    def test_casi_con_punteggi_diversi(self):
        def csp_points(headers):
            ctx = ScanContext(domain="example.com")
            ctx.https_response = fake("https://example.com/", 200, headers)
            return by_name(HeadersChecker(HttpFetcher()).run(ctx))["Content-Security-Policy"].points

        absent = csp_points({})
        report_only = csp_points({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        unsafe = csp_points({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
        strong = csp_points({"Content-Security-Policy": "default-src 'self'; object-src 'none'"})
        self.assertEqual(absent, 0)
        self.assertEqual(unsafe, CspAnalyzer.POINTS_NO_XSS)
        self.assertEqual(strong, CspAnalyzer.MAX_POINTS)
        self.assertTrue(absent < report_only < unsafe < strong)

    def test_unsafe_inline_con_nonce_non_conta(self):
        points, _ = CspAnalyzer("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'").score()
        self.assertEqual(points, CspAnalyzer.MAX_POINTS)


class TestRispostaBloccata(unittest.TestCase):
    AKAMAI_403 = fake("https://www.zalando.it/", 403, {"Server": "AkamaiNetStorage", "X-Edge-Error": "halt"},
                      "<html><body>Access Denied</body></html>")

    def test_403_di_un_waf_e_riconosciuto(self):
        self.assertEqual(detect_bot_block(self.AKAMAI_403), "Akamai")

    def test_header_della_pagina_di_blocco_non_valutati(self):
        ctx = ScanContext(domain="www.zalando.it")
        ctx.https_response = self.AKAMAI_403
        checks = by_name(HeadersChecker(HttpFetcher()).run(ctx))
        self.assertEqual(ctx.bot_block, "Akamai")
        for c in checks.values():
            self.assertTrue(c.skipped, c.name)
            self.assertIs(c.skip_reason, Skip.BOT_BLOCK, c.name)
            self.assertEqual(c.points, 0, c.name)

    def test_errori_generici_non_affidabili(self):
        for status in (401, 403, 429, 500, 503):
            self.assertEqual(detect_unreliable(fake("https://x.it/", status, {"Server": "nginx"})), f"HTTP {status}")
        self.assertIsNone(detect_unreliable(fake("https://x.it/", 200, {"Server": "nginx"})))
        # un 403 qualsiasi NON e' la firma di un WAF
        self.assertIsNone(detect_bot_block(fake("https://x.it/", 403, {"Server": "nginx"})))

    def test_si_preferisce_la_risposta_non_bloccata(self):
        ok = fake("https://www.zalando.it/", 200, {"Server": "nginx"})
        f = HttpFetcher()
        with mock.patch.object(HttpFetcher, "_fetch", side_effect=[(self.AKAMAI_403, None), (ok, None)]):
            resp, _ = f.best("https://www.zalando.it/")
        self.assertIs(resp, ok)


class TestTlsLegacy(unittest.TestCase):
    def setUp(self):
        self.ctx = ScanContext(domain="example.com")
        self.ctx.https_response = chain(redirect("https://example.com/", "https://www.example.com/", 301),
                                        fake("https://www.example.com/", 200))

    def run_with(self, accepted):
        with mock.patch.object(TlsChecker, "_probe_legacy", lambda self, host: accepted[host]):
            return by_name(TlsChecker(HttpFetcher())._legacy_protocols(self.ctx))

    def test_tls10_solo_sull_host_di_redirect_e_minore(self):
        checks = self.run_with({"example.com": ["TLSv1"], "www.example.com": []})
        main = checks["TLS 1.0/1.1 disabilitati"]
        minor = checks["TLS 1.0/1.1 sull'host di redirect"]
        self.assertEqual(main.points, main.max_points)          # host finale ok
        self.assertIn("www.example.com", main.message)
        self.assertEqual(minor.points, 0)                       # segnalato...
        self.assertEqual(minor.severity, Severity.INFO)         # ...ma solo come informativo
        self.assertLess(minor.max_points, main.max_points)      # e pesa meno

    def test_tls10_sull_host_finale_pesa_di_piu(self):
        checks = self.run_with({"example.com": [], "www.example.com": ["TLSv1", "TLSv1.1"]})
        self.assertEqual(checks["TLS 1.0/1.1 disabilitati"].points, 0)
        self.assertEqual(checks["TLS 1.0/1.1 disabilitati"].severity, Severity.MEDIA)

    def test_non_testabile_localmente(self):
        checks = self.run_with({"example.com": None, "www.example.com": None})
        self.assertTrue(all(c.skipped and c.skip_reason is Skip.LOCAL_LIMIT for c in checks.values()))


class TestPrimoSaltoHttp(unittest.TestCase):
    def http_points(self, response):
        ctx = ScanContext(domain="example.com")
        ctx.http_response = response
        return HttpsChecker(HttpFetcher())._http_redirect(ctx).points

    def test_salto_diretto_a_https(self):
        self.assertEqual(self.http_points(chain(redirect("http://example.com/", "https://example.com/", 301),
                                                fake("https://example.com/"))), 5)

    def test_https_solo_dopo_un_salto_in_chiaro(self):
        self.assertEqual(self.http_points(chain(redirect("http://example.com/", "http://www.example.com/", 301),
                                                redirect("http://www.example.com/", "https://www.example.com/", 301),
                                                fake("https://www.example.com/"))), 3)

    def test_http_senza_redirect(self):
        self.assertEqual(self.http_points(fake("http://example.com/")), 0)


if __name__ == "__main__":
    unittest.main()
