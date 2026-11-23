"""
Marchio dichiarato dalla pagina e verifica del suo sito ufficiale su Wikidata.

Idea: una pagina di phishing deve dire di essere qualcuno ("PayPal - Accedi").
Se il marchio che dichiara ha un sito ufficiale diverso dal dominio che la serve,
e' un forte indizio di contraffazione, qualunque sia il marchio.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

import requests

from ..fetcher import HttpFetcher
from .brands import BrandCatalog, split_domain
from .similarity import compact

TITLE_SEPARATORS = re.compile(r"\s+[|\-–—:·•»]\s+")
MAX_HTML = 500_000
LEGAL_WORDS = {
    "spa", "srl", "srls", "sas", "snc", "inc", "ltd", "llc", "plc", "corp", "corporation", "company",
    "co", "gmbh", "ag", "sa", "nv", "bv", "group", "gruppo", "holding", "holdings", "com", "it", "net", "org",
}


def brand_key(text: str) -> str:
    """
    Nome del marchio senza forme societarie ed estensioni:
    'Ferrero S.p.A.' -> 'ferrero', 'Amazon.com' -> 'amazon', 'Gruppo Intesa Sanpaolo' -> 'intesasanpaolo'.
    """
    tokens = re.findall(r"[a-z0-9]+", compact_spaced(text))
    merged: list[str] = []
    for tok in tokens:  # 's.p.a.' arriva come 's','p','a': lo ricompongo
        if len(tok) == 1 and merged and merged[-1].isalpha() and len(merged[-1]) <= 3 and merged[-1] not in LEGAL_WORDS:
            merged[-1] += tok
        else:
            merged.append(tok)
    while len(merged) > 1 and merged[-1] in LEGAL_WORDS:
        merged.pop()
    while len(merged) > 1 and merged[0] in LEGAL_WORDS:
        merged.pop(0)
    return "".join(merged)


def compact_spaced(text: str) -> str:
    """Minuscolo e senza accenti, ma mantiene i separatori tra le parole."""
    import unicodedata
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


# --------------------------------------------------------------------------- #
# Lettura della pagina
# --------------------------------------------------------------------------- #
class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta: dict[str, str] = {}
        self.has_password = False
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (a.get("property") or a.get("name") or "").lower()
            if key in ("og:site_name", "application-name", "og:title", "apple-mobile-web-app-title"):
                self.meta.setdefault(key, a.get("content", "").strip())
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


@dataclass
class PageInfo:
    title: str = ""
    site_name: str = ""
    app_name: str = ""
    has_password: bool = False

    def candidates(self) -> list[tuple[str, str]]:
        """Nomi con cui la pagina si presenta, dal piu' affidabile: (nome, fonte)."""
        out: list[tuple[str, str]] = []
        if self.site_name:
            out.append((self.site_name, "og:site_name"))
        if self.app_name:
            out.append((self.app_name, "application-name"))
        pieces = [p.strip() for p in TITLE_SEPARATORS.split(self.title) if p.strip()]
        if not out and pieces:
            # senza meta tag il nome del sito sta di solito in fondo al titolo; l'inizio del titolo
            # ("Apple - Notizie | TechBlog") e' spesso l'argomento, quindi lo usiamo solo nelle
            # pagine di login, dove il phishing mette il marchio imitato
            out.append((pieces[-1], "titolo"))
            if len(pieces) > 1 and self.has_password:
                out.append((pieces[0], "titolo"))
        seen, unique = set(), []
        for name, source in out:
            key = compact(name)
            if 2 < len(name) <= 60 and key and key not in seen:
                seen.add(key)
                unique.append((name, source))
        return unique


class PageInspector:
    @staticmethod
    def inspect(html: str) -> PageInfo:
        parser = _MetaParser()
        try:
            parser.feed(html[:MAX_HTML])
        except Exception:
            pass  # HTML malformato: teniamo quello che e' stato letto
        return PageInfo(
            title=" ".join(parser.title.split()),
            site_name=parser.meta.get("og:site_name", ""),
            app_name=parser.meta.get("application-name", "") or parser.meta.get("apple-mobile-web-app-title", ""),
            has_password=parser.has_password,
        )


# --------------------------------------------------------------------------- #
# Wikidata
# --------------------------------------------------------------------------- #
@dataclass
class WikidataEntity:
    qid: str
    label: str
    description: str
    official_domains: list[str]


class WikidataClient:
    """Cerca un marchio per nome e restituisce i suoi siti ufficiali (proprieta' P856)."""

    API = "https://www.wikidata.org/w/api.php"
    SPARQL = "https://query.wikidata.org/sparql"

    def __init__(self, fetcher: HttpFetcher):
        self.fetcher = fetcher
        self._cache: dict[str, list[WikidataEntity]] = {}

    def lookup(self, name: str) -> list[WikidataEntity] | None:
        """Entita' trovate ([] = nessuna), oppure None se Wikidata non ha risposto."""
        key = compact(name)
        if key not in self._cache:
            result = self._lookup(name)
            if result is None:
                return None  # errore di rete o limite di richieste: non lo memorizzo
            self._cache[key] = result
        return self._cache[key]

    def _lookup(self, name: str) -> list[WikidataEntity] | None:
        try:
            r = self.fetcher.get(self.API, params={
                "action": "wbsearchentities", "search": name, "language": "it", "uselang": "it",
                "type": "item", "limit": 15, "format": "json",
            })
            if not r.ok:
                return None
            results = r.json().get("search", [])
        except (requests.RequestException, ValueError):
            return None

        # solo le entita' il cui nome (o alias) corrisponde, a meno di forme societarie ed estensioni
        wanted = brand_key(name)
        items = {res["id"]: res for res in results
                 if brand_key(res.get("match", {}).get("text", "")) == wanted}
        if not items:
            return []

        values = " ".join(f"wd:{qid}" for qid in items)
        query = f"SELECT ?item ?site WHERE {{ VALUES ?item {{ {values} }} ?item wdt:P856 ?site . }}"
        try:
            r = self.fetcher.get(self.SPARQL, params={"query": query, "format": "json"},
                                 headers={"Accept": "application/sparql-results+json"})
            if not r.ok:
                return None
            bindings = r.json()["results"]["bindings"]
        except (requests.RequestException, ValueError, KeyError):
            return None

        sites: dict[str, set[str]] = {}
        for b in bindings:
            qid = b["item"]["value"].rsplit("/", 1)[-1]
            host = re.sub(r"^https?://", "", b["site"]["value"]).split("/")[0].split(":")[0].lower()
            parts = split_domain(host)
            if parts.name and parts.suffix:
                sites.setdefault(qid, set()).add(parts.registrable)
        # stesso ordine della ricerca di Wikidata: la prima entita' e' la piu' rilevante
        return [
            WikidataEntity(qid, items[qid].get("label", ""), items[qid].get("description", ""), sorted(sites[qid]))
            for qid in items if qid in sites
        ]


# --------------------------------------------------------------------------- #
# Verifica del marchio dichiarato
# --------------------------------------------------------------------------- #
@dataclass
class BrandClaim:
    """
    status:
      ufficiale          il dominio e' un sito ufficiale del marchio dichiarato
      coerente           il nome dichiarato corrisponde al dominio (nessuna prova contraria)
      non_corrispondente la pagina dice di essere un marchio il cui sito ufficiale e' un altro
      sconosciuto        marchio dichiarato non trovato nelle fonti
    """

    name: str
    source: str
    status: str
    brand: str = ""
    official_domains: list[str] = field(default_factory=list)
    wikidata_id: str | None = None
    wikidata_description: str = ""
    verified_by: str = ""
    has_password: bool = False
    lookup_failed: bool = False  # Wikidata non ha risposto: verifica incompleta


class BrandClaimVerifier:
    MAX_LOOKUPS = 3

    def __init__(self, fetcher: HttpFetcher, catalog: BrandCatalog):
        self.catalog = catalog
        self.wikidata = WikidataClient(fetcher)
        self._catalog_by_key = {}
        for brand, domains in catalog.brands.items():
            self._catalog_by_key[compact(brand)] = brand
            for d in domains:
                self._catalog_by_key.setdefault(split_domain(d).name.replace("-", ""), brand)

    def verify(self, html: str, registrable: str, final_registrable: str | None) -> BrandClaim | None:
        page = PageInspector.inspect(html)
        serving = {registrable} | ({final_registrable} if final_registrable else set())
        own_name = compact(split_domain(registrable).name)

        fallback: BrandClaim | None = None
        for name, source in page.candidates()[: self.MAX_LOOKUPS]:
            claim = self._check(name, source, serving, own_name)
            claim.has_password = page.has_password
            if claim.status in ("ufficiale", "non_corrispondente"):
                return claim
            fallback = fallback or claim

        # marchi noti citati nel titolo di una pagina di login ("Accedi al tuo conto PayPal"):
        # solo con un campo password, altrimenti ogni articolo che parla di Google sarebbe sospetto
        title_key = compact(page.title) if page.has_password else ""
        for key, brand in self._catalog_by_key.items():
            if len(key) >= 5 and key in title_key and not (serving & set(self.catalog.official_domains(brand))):
                if key not in own_name:
                    return BrandClaim(page.title, "titolo (marchio noto)", "non_corrispondente", brand=brand,
                                      official_domains=self.catalog.official_domains(brand),
                                      verified_by="catalogo", has_password=page.has_password)
        return fallback

    def _check(self, name: str, source: str, serving: set[str], own_name: str) -> BrandClaim:
        key = compact(name)
        officials: set[str] = set()
        claim = BrandClaim(name=name, source=source, status="sconosciuto", brand=name)

        catalog_brand = self._catalog_by_key.get(key)
        if catalog_brand:
            officials |= set(self.catalog.official_domains(catalog_brand))
            claim.brand, claim.verified_by = catalog_brand, "catalogo"

        entities = self.wikidata.lookup(name)
        if entities is None:
            claim.lookup_failed, entities = True, []
        for e in entities:
            officials |= set(e.official_domains)
        if entities:
            claim.wikidata_id, claim.wikidata_description = entities[0].qid, entities[0].description
            claim.brand = entities[0].label or claim.brand
            claim.verified_by = "Wikidata" if not claim.verified_by else claim.verified_by + " + Wikidata"

        claim.official_domains = sorted(officials)
        if not officials:
            # nessuna fonte: possiamo solo dire se il nome e' coerente con il dominio
            claim.status = "coerente" if len(key) >= 4 and (key in own_name or own_name in key) else "sconosciuto"
            return claim
        if serving & officials:
            claim.status = "ufficiale"
        elif own_name in {compact(split_domain(d).name) for d in officials}:
            claim.status = "coerente"  # stesso nome del sito ufficiale, estensione diversa (es. amazon.nl)
        elif own_name == brand_key(name):
            claim.status = "coerente"  # barilla.com per 'Barilla' (Wikidata indica barillagroup.com)
        else:
            claim.status = "non_corrispondente"
        return claim
