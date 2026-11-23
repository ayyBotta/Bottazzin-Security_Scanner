"""Raccolta delle risposte HTTP/HTTPS del dominio."""

from __future__ import annotations

import requests
import urllib3

from .antibot import detect_bot_block
from .models import ScanContext

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10  # oltre: catena anomala, la richiesta fallisce (TooManyRedirects)
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
}


class HttpFetcher:
    """Wrapper attorno a requests con timeout e User-Agent comuni."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        self.session.max_redirects = MAX_REDIRECTS

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(url, **kwargs)

    def collect(self, ctx: ScanContext) -> None:
        """
        Scarica la homepage in HTTPS e HTTP e salva le risposte nel contesto.

        Ogni URL viene chiesto due volte: come un browser e come lo scanner. Alcuni siti decidono cosa
        servire dallo User-Agent (google.com manda HSTS e il redirect HTTP -> HTTPS solo ai browser che
        riconosce), quindi conta la risposta "da browser", cioe' quella che vedono gli utenti. Altri
        siti invece bloccano proprio i finti browser (zalando.it, subito.it): in quel caso si usa la
        risposta "da scanner".
        """
        ctx.https_response, ctx.https_error = self.best(f"https://{ctx.domain}/")
        ctx.http_response, _ = self.best(f"http://{ctx.domain}/")

    def best(self, url: str, headers: dict | None = None) -> tuple[requests.Response | None, str | None]:
        """La risposta piu' rappresentativa tra quella "da browser" e quella "da scanner", con l'eventuale
        errore SSL. `headers` si aggiunge a entrambe (es. Origin per il test CORS)."""
        extra = headers or {}
        browser, browser_err = self._fetch(url, {**BROWSER_HEADERS, **extra})
        plain, plain_err = self._fetch(url, extra or None)
        for resp, err in ((browser, browser_err), (plain, plain_err)):
            if resp is not None and resp.status_code < 400 and detect_bot_block(resp) is None:
                return resp, err
        # entrambe bloccate o in errore: meglio una risposta (anche di blocco) che nessuna
        if browser is not None:
            return browser, browser_err
        return plain, plain_err or browser_err

    def _fetch(self, url: str, headers: dict | None = None) -> tuple[requests.Response | None, str | None]:
        """GET senza cookie di richieste precedenti; se il certificato non e' valido riprova senza verifica
        (per poter comunque analizzare gli header) e restituisce l'errore."""
        # ogni richiesta parte "pulita", come un primo visitatore: niente cookie e connessione nuova
        # (google.com manda HSTS solo sulla prima risposta di ogni connessione)
        self.session.cookies.clear()
        self.session.close()
        try:
            return self.get(url, headers=headers), None
        except requests.exceptions.SSLError as e:
            err = f"Errore SSL: {e.__class__.__name__}"
            try:
                self.session.cookies.clear()
                return self.get(url, headers=headers, verify=False), err
            except requests.RequestException:
                return None, err
        except requests.RequestException as e:
            return None, e.__class__.__name__

    @staticmethod
    def raw_set_cookies(resp: requests.Response) -> list[str]:
        """Header Set-Cookie grezzi (requests li unisce e perde i flag)."""
        hdrs = getattr(getattr(resp, "raw", None), "headers", None)
        if hdrs is not None and hasattr(hdrs, "getlist"):
            return hdrs.getlist("Set-Cookie")
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []
