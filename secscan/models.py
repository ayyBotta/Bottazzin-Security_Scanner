"""Strutture dati condivise da tutto lo scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from urllib.parse import urlparse

import requests
from requests.structures import CaseInsensitiveDict

from .antibot import detect_unreliable
from .domains import split_domain


class Severity(IntEnum):
    """Gravita' di un fattore di pericolosita'."""

    INFO = 0
    BASSA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class SkipReason:
    """Motivo per cui un controllo e' escluso dal calcolo (non conta ne' a favore ne' contro)."""

    label: str  # breve, per le categorie: "protezione anti-bot"
    text: str   # perche' il controllo non si puo' o non si deve valutare


class Skip:
    """Motivi di esclusione usati dai checker."""

    REDIRECT = SkipReason(
        "dominio di solo redirect",
        "Il dominio non mostra pagine proprie: rimanda subito a un altro sito. Queste protezioni servono "
        "alle pagine (script, iframe, file, dati letti da altri siti), quindi riguardano il sito di "
        "destinazione, che viene valutato a parte.")
    REDIRECT_CERT = SkipReason(
        "certificato di un dominio di solo redirect",
        "Il dominio rimanda subito a un altro sito e non raccoglie dati: un certificato non valido non "
        "espone informazioni degli utenti, quindi non viene penalizzato (e senza un certificato valido "
        "scadenza e versione TLS non si possono leggere). Resta il fastidio: chi apre la versione "
        "https:// vede un avviso del browser.")
    BOT_BLOCK = SkipReason(
        "richiesta bloccata",
        "Risultato non affidabile: al posto della homepage e' arrivata una pagina di blocco o di errore "
        "(protezione anti-bot del sito, oppure una risposta 401/403/429/5xx). Header, cookie e banner di "
        "quella pagina non sono quelli del sito vero: giudicarli darebbe un risultato falso, in un senso o "
        "nell'altro. La protezione anti-bot in se' non e' un problema di sicurezza.")
    CERT_INVALID = SkipReason(
        "certificato non valido",
        "Il certificato non e' valido, quindi non si puo' stabilire una connessione verificata e i dati "
        "della connessione non sono affidabili. Il problema e' gia' penalizzato dal controllo "
        "\"Certificato valido\": contarlo di nuovo qui lo punirebbe due volte.")
    TLS_FAILED = SkipReason(
        "connessione TLS fallita",
        "La connessione sicura con il server non si e' completata (rete lenta, server che non risponde "
        "sulla porta 443 o che chiude la connessione). Senza connessione il dato non si puo' leggere: "
        "penalizzare il sito per un errore di rete sarebbe ingiusto.")
    REQUEST_FAILED = SkipReason(
        "richiesta fallita",
        "La richiesta di prova al server non ha avuto risposta (timeout o errore di rete). Senza risposta "
        "non si puo' sapere come e' configurato il sito.")
    NO_BRAND = SkipReason(
        "nessun marchio dichiarato",
        "La pagina non si presenta con il nome di un marchio (titolo, nome del sito): non c'e' "
        "un'identita' da confrontare con il dominio, quindi non c'e' niente da verificare.")
    WIKIDATA = SkipReason(
        "Wikidata non raggiungibile",
        "Per sapere qual e' il sito ufficiale del marchio dichiarato dalla pagina serve Wikidata, che non ha "
        "risposto. Meglio escludere il controllo che dare un giudizio senza prove.")
    NO_AGE = SkipReason(
        "data di registrazione non disponibile",
        "Il registro del dominio (RDAP/WHOIS) non ha fornito la data di registrazione: diversi registri, "
        "soprattutto delle estensioni nazionali, non la pubblicano. E' un limite della fonte, non del sito.")
    LOCAL_LIMIT = SkipReason(
        "limite dello scanner",
        "Il controllo non si puo' eseguire da questo computer (manca una libreria o la versione installata "
        "non lo permette): e' un limite dello scanner, non un problema del sito.")


@dataclass
class Check:
    """
    Risultato di un singolo controllo.

    severity  gravita' del problema se il controllo fallisce completamente
    why       perche' il problema e' pericoloso (quale attacco rende possibile)
    lost_points  punti di sicurezza persi sul totale di 100 (calcolato dallo SecurityScorer)
    """

    category: str
    name: str
    max_points: int
    severity: Severity = Severity.MEDIA
    why: str = ""
    points: float = 0
    message: str = ""
    skipped: bool = False
    lost_points: float = 0
    skip_reason: "SkipReason | None" = None
    source_url: str | None = None  # URL della risposta su cui e' stato rilevato il dato ("Rilevato su")

    def skip(self, message: str, reason: "SkipReason") -> None:
        """Esclude il controllo dal calcolo: `message` dice cosa e' successo su questo dominio,
        `reason` spiega perche' in quel caso e' giusto non contarlo."""
        self.skipped, self.message, self.skip_reason = True, message, reason
        self.points = 0  # escluso = nessun punto, ne' a favore ne' contro

    @property
    def status(self) -> str:
        if self.skipped:
            return "SKIP"
        if self.points >= self.max_points:
            return "OK"
        if self.points > 0:
            return "WARN"
        return "FAIL"

    @property
    def is_finding(self) -> bool:
        """True se il controllo rappresenta un fattore di pericolosita'."""
        return self.status in ("WARN", "FAIL")

    @property
    def effective_severity(self) -> Severity:
        """Gravita' ridotta se il problema e' solo parziale."""
        ratio = self.points / self.max_points if self.max_points else 1
        if ratio >= 0.75:
            return Severity(max(self.severity - 2, Severity.INFO))
        if ratio >= 0.5:
            return Severity(max(self.severity - 1, Severity.INFO))
        return self.severity


@dataclass
class ScoreCap:
    """Punteggio massimo raggiungibile a causa di un problema critico."""

    max_score: int
    reason: str


@dataclass
class LookalikeResult:
    """
    Verdetto sulla legittimita' del dominio rispetto ai domini noti.

    verdict: UFFICIALE | LEGITTIMO | NON SOSPETTO | SOSPETTO | LOOKALIKE
    """

    domain: str                     # forma ASCII (punycode)
    display: str                    # forma Unicode, come la vede l'utente
    registrable: str
    verdict: str = "NON SOSPETTO"
    description: str = ""
    brand: str | None = None        # marchio imitato o di appartenenza
    target: str | None = None       # dominio ufficiale imitato
    technique: str | None = None
    reasons: list[str] = field(default_factory=list)
    skeleton: str = ""
    scripts: list[str] = field(default_factory=list)
    confusables: list[dict] = field(default_factory=list)
    age_days: int | None = None
    created: str | None = None
    age_source: str | None = None
    tranco_rank: int | None = None   # posizione del dominio tra i piu' visitati (None = oltre i 100.000)
    target_rank: int | None = None   # posizione del dominio imitato, se trovato tramite Tranco
    match_source: str | None = None  # "catalogo" o "Tranco"
    page_claim: dict | None = None   # marchio dichiarato dalla pagina e verifica su Wikidata
    sources: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Dati raccolti sul dominio, condivisi tra i checker."""

    domain: str
    https_response: requests.Response | None = None
    http_response: requests.Response | None = None
    https_error: str | None = None
    cert_valid: bool | None = None
    cert: dict | None = None
    lookalike: LookalikeResult | None = None
    caps: list[ScoreCap] = field(default_factory=list)
    _bot_block_resp: requests.Response | None = field(default=None, repr=False, compare=False)
    _bot_block: str | None = field(default=None, repr=False, compare=False)

    @property
    def final_host(self) -> str | None:
        """Host finale dopo i redirect della homepage."""
        resp = self.main_response
        return urlparse(resp.url).hostname if resp is not None else None

    @property
    def registrable(self) -> str:
        return split_domain(self.domain).registrable

    @property
    def redirect_target(self) -> str | None:
        """Host di destinazione se la homepage rimanda a un ALTRO sito (gooogle.com -> www.google.com).
        I redirect interni (google.com -> www.google.com) non contano."""
        host = self.final_host
        if host and split_domain(host).registrable != self.registrable:
            return host
        return None

    def own_response(self, resp: requests.Response | None) -> requests.Response | None:
        """Ultima risposta della catena di redirect servita dal dominio stesso (non dalla destinazione)."""
        if resp is None:
            return None
        own = None
        for hop in [*resp.history, resp]:
            host = urlparse(hop.url).hostname or ""
            if split_domain(host).registrable == self.registrable:
                own = hop
        return own if own is not None else resp

    @property
    def own_https_response(self) -> requests.Response | None:
        return self.own_response(self.https_response)

    @property
    def own_main_response(self) -> requests.Response | None:
        return self.own_response(self.main_response)

    @property
    def own_https_hops(self) -> list[requests.Response]:
        """Risposte HTTPS della catena servite dal dominio stesso, in ordine (es. https://google.com 301,
        poi https://www.google.com 200). L'ultima e' quella su cui si leggono gli header."""
        resp = self.https_response
        if resp is None:
            return []
        hops = [h for h in [*resp.history, resp]
                if urlparse(h.url).scheme == "https"
                and split_domain(urlparse(h.url).hostname or "").registrable == self.registrable]
        own = self.own_https_response
        return hops[:hops.index(own) + 1] if own in hops else hops

    @property
    def own_final_host(self) -> str | None:
        """Ultimo host dello stesso dominio registrabile (es. www.google.com per google.com)."""
        resp = self.own_main_response
        return urlparse(resp.url).hostname if resp is not None else None

    @property
    def bot_block(self) -> str | None:
        """Protezione anti-bot (es. "AWS WAF") che ha risposto al posto della homepage, se c'e'.
        Si guarda la risposta del dominio stesso: per un dominio di solo redirect conta il redirect."""
        resp = self.own_main_response
        if resp is not self._bot_block_resp:
            self._bot_block_resp, self._bot_block = resp, detect_unreliable(resp)
        return self._bot_block

    @property
    def reachable(self) -> bool:
        return self.https_response is not None or self.http_response is not None

    @property
    def main_response(self) -> requests.Response | None:
        # niente `or`: una Response 4xx/5xx vale False e verrebbe scartata
        return self.https_response if self.https_response is not None else self.http_response

    @property
    def headers(self) -> CaseInsensitiveDict:
        """Header serviti dal dominio stesso (in caso di redirect: quelli della risposta di redirect)."""
        resp = self.own_main_response
        return resp.headers if resp is not None else CaseInsensitiveDict()

    def add_cap(self, max_score: int, reason: str) -> None:
        self.caps.append(ScoreCap(max_score, reason))


@dataclass
class RiskLevel:
    """Qualificazione del livello di rischio corrispondente al punteggio."""

    name: str
    description: str


@dataclass
class ScanResult:
    """Esito finale di una scansione."""

    domain: str
    score: int
    level: RiskLevel
    checks: list[Check]
    caps: list[ScoreCap]
    lookalike: LookalikeResult | None = None
    redirect_target: str | None = None          # il dominio rimanda a questo host di un altro sito
    destination: "ScanResult | None" = None     # scansione separata della destinazione
    bot_block: str | None = None                # protezione anti-bot che ha risposto al posto della pagina
    chains: dict[str, list[tuple[int, str]]] = field(default_factory=dict)  # "HTTPS"/"HTTP" -> [(stato, url)]

    @property
    def findings(self) -> list[Check]:
        """Fattori di pericolosita', dal piu' grave al meno grave."""
        found = [c for c in self.checks if c.is_finding]
        return sorted(found, key=lambda c: (c.effective_severity, c.lost_points), reverse=True)
