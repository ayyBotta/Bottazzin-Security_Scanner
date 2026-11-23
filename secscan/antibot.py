"""Riconosce le risposte delle protezioni anti-bot (WAF / bot manager) al posto della pagina vera.

Molti siti grandi (Amazon, eBay, Booking, Etsy...) davanti a un client automatico non servono la
homepage ma una pagina di verifica ("challenge") o di accesso negato, generata dal firewall. Gli
header e i cookie di quella pagina sono del firewall, non del sito: valutarli come se fossero la
homepage produce falsi positivi (CSP, HSTS, clickjacking "assenti" anche se il sito vero li ha).
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

BODY_LIMIT = 40_000  # i marcatori stanno all'inizio della pagina

# (marcatore nel corpo, in minuscolo) -> protezione
BODY_MARKERS: list[tuple[str, str]] = [
    ("awswafintegration", "AWS WAF"),
    ("awswafcookiedomainlist", "AWS WAF"),
    ("_cf_chl_opt", "Cloudflare"),
    ("cf-chl-", "Cloudflare"),
    ("<title>just a moment...</title>", "Cloudflare"),
    ("attention required! | cloudflare", "Cloudflare"),
    ("bm-verify=", "Akamai Bot Manager"),
    ("triggerinterstitialchallenge", "Akamai Bot Manager"),
    ("captcha-delivery.com", "DataDome"),
    ("_incapsula_resource", "Imperva"),
    ("incapsula incident id", "Imperva"),
    ("px-captcha", "HUMAN (PerimeterX)"),
    ("sucuri website firewall", "Sucuri"),
    ("<title>pardon our interruption", "Imperva / Distil"),
]

# la homepage ha rimandato a una pagina di verifica dello stesso sito (es. eBay: /splashui/challenge)
URL_MARKERS = ("/challenge", "/captcha", "/splashui/")

# protezioni riconoscibili dal banner Server, usate solo insieme a un codice di blocco
SERVER_SIGNATURES: list[tuple[str, str]] = [
    ("akamai", "Akamai"),
    ("cloudflare", "Cloudflare"),
    ("cloudfront", "AWS CloudFront"),
    ("datadome", "DataDome"),
    ("sucuri", "Sucuri"),
]

BLOCK_STATUS = {401, 403, 429, 503}


def blocked_message(protection: str) -> str:
    """Cosa e' successo, per i controlli esclusi perche' la richiesta e' stata bloccata."""
    if protection.startswith("HTTP "):
        return f"Richiesta bloccata o in errore: il server ha risposto {protection} invece della homepage"
    return f"Richiesta bloccata: ha risposto la protezione {protection} invece della homepage"


def detect_unreliable(resp: requests.Response | None) -> str | None:
    """Come detect_bot_block, ma considera non affidabile anche qualsiasi 401/403/429/5xx: una pagina
    di errore non porta gli header del sito vero. Restituisce la protezione o "HTTP <codice>"."""
    found = detect_bot_block(resp)
    if found or resp is None:
        return found
    if resp.status_code in BLOCK_STATUS or resp.status_code >= 500:
        return f"HTTP {resp.status_code}"
    return None


def detect_bot_block(resp: requests.Response | None) -> str | None:
    """Nome della protezione anti-bot che ha risposto al posto del sito, oppure None."""
    if resp is None:
        return None
    h = resp.headers

    # 1. header espliciti dei WAF
    if h.get("x-amzn-waf-action"):
        return "AWS WAF"
    if h.get("cf-mitigated", "").lower() == "challenge":
        return "Cloudflare"
    if h.get("x-sucuri-block"):
        return "Sucuri"
    if h.get("x-datadome") and resp.status_code in BLOCK_STATUS:
        return "DataDome"

    # 2. marcatori nel corpo delle pagine di verifica
    try:
        body = resp.text[:BODY_LIMIT].lower()
    except Exception:
        body = ""
    for marker, name in BODY_MARKERS:
        if marker in body:
            return name
    path = urlparse(resp.url or "").path.lower()
    if resp.history and any(m in path for m in URL_MARKERS):
        return "anti-bot del sito"

    # 3. codice di blocco servito da una piattaforma di protezione nota
    #    (un 403 di un server qualsiasi NON basta: potrebbe essere la vera risposta del sito)
    if resp.status_code in BLOCK_STATUS:
        server = h.get("Server", "").lower()
        for sig, name in SERVER_SIGNATURES:
            if sig in server:
                return name
        if "errors.edgesuite.net" in body:
            return "Akamai"
    return None
