"""Tutti i checker disponibili, nell'ordine in cui vengono eseguiti."""

from .base import BaseChecker
from .dns_email import DnsChecker
from .headers import CspAnalyzer, HeadersChecker
from .lookalike import LookalikeChecker
from .tls import HttpsChecker, TlsChecker
from .web import CookieChecker, CorsChecker, DisclosureChecker, SecurityTxtChecker

# TlsChecker deve girare prima di LookalikeChecker, CORS e security.txt:
# imposta ctx.cert_valid e ctx.cert
DEFAULT_CHECKERS: list[type[BaseChecker]] = [
    HttpsChecker,
    TlsChecker,
    LookalikeChecker,
    HeadersChecker,
    CookieChecker,
    DisclosureChecker,
    CorsChecker,
    DnsChecker,
    SecurityTxtChecker,
]

__all__ = [
    "BaseChecker", "CspAnalyzer", "DEFAULT_CHECKERS",
    "HttpsChecker", "TlsChecker", "HeadersChecker", "CookieChecker",
    "DisclosureChecker", "CorsChecker", "DnsChecker", "SecurityTxtChecker", "LookalikeChecker",
]
