"""
Riconoscimento dei domini lookalike (omografi, typosquatting, combosquatting...).

Il verdetto si costruisce cosi':
  1. il dominio e' nel catalogo dei domini ufficiali?                    -> UFFICIALE
  2. assomiglia a un dominio noto?  prima il catalogo curato, poi i
     100.000 siti piu' visitati (classifica Tranco)                       -> SOSPETTO / LOOKALIKE
  3. ci sono prove che appartenga allo stesso proprietario?
     (certificato, nameserver, redirect al sito ufficiale)               -> LEGITTIMO
  4. la pagina dice di essere un marchio? il suo sito ufficiale
     (catalogo o Wikidata) coincide con il dominio?                       -> UFFICIALE / LOOKALIKE
  5. eta' del dominio e popolarita' rafforzano o attenuano il verdetto.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..fetcher import HttpFetcher
from ..models import LookalikeResult
from .age import DomainAgeLookup
from .brands import BrandCatalog, DomainParts, split_domain
from .confusables import Confusables, IdnInfo
from .page_brand import BrandClaim, BrandClaimVerifier
from .similarity import describe_diff, osa_distance, to_unicode
from .tranco import TrancoHit, TrancoIndex, load_tranco

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

TECH_SUBDOMAIN = "Marchio nel sottodominio"
TECH_IDN = "Omografo IDN"
TECH_CHARS = "Sostituzione di caratteri simili"
TECH_HYPHEN = "Trattino inserito"
TECH_COMBO = "Combosquatting (parole aggiunte)"
TECH_TYPO = "Typosquatting (errore di battitura)"
TECH_TLD = "Estensione diversa"
TECH_IMPERSONATION = "Impersonificazione del marchio"

PRIORITY = [TECH_SUBDOMAIN, TECH_IDN, TECH_CHARS, TECH_HYPHEN, TECH_TYPO, TECH_COMBO, TECH_TLD]
VERDICT_ORDER = ["UFFICIALE", "LEGITTIMO", "NON SOSPETTO", "SOSPETTO", "LOOKALIKE"]

SUSPICIOUS_WORDS = [
    "login", "signin", "secure", "security", "verify", "verifica", "account", "update", "aggiorna",
    "support", "assistenza", "help", "auth", "wallet", "bank", "banking", "pay", "conferma", "accesso",
    "sicurezza", "rimborso", "refund", "bonus", "gift", "premio", "service", "servizi", "online", "web",
    "app", "id", "password", "unlock", "sblocco", "alert", "avviso", "clienti", "customer",
]

DESCRIPTIONS = {
    "UFFICIALE": "E' un dominio ufficiale di {brand}.",
    "LEGITTIMO": "Assomiglia a {target}, ma ci sono prove concrete che appartenga allo stesso proprietario "
                 "(dominio collegato o registrazione difensiva).",
    "NON SOSPETTO": "Non imita nessuno dei domini noti controllati (catalogo e siti piu' visitati) e non usa "
                    "caratteri ingannevoli. Questo non certifica il sito: indica solo che non imita marchi conosciuti.",
    "SOSPETTO": "Presenta somiglianze con {target} o tratti tipici dei domini ingannevoli: "
                "verifica con attenzione prima di inserire dati.",
    "SOSPETTO_NO_TARGET": "Usa caratteri che possono trarre in inganno, anche se non imita un dominio noto.",
    "LOOKALIKE": "Molto probabilmente imita {target} ({brand}): non inserire credenziali, "
                 "dati personali o di pagamento.",
}

# Soglie per i confronti con la classifica Tranco (piu' e' alto il rank, meno e' probabile il bersaglio)
TRANCO_STRONG_RANK = 10_000
TRANCO_TYPO_STRONG_RANK = 1_000
TRANCO_TLD_RANK = 5_000
POPULAR_RANK = 10_000


@dataclass
class Match:
    brand: str
    target: str
    technique: str
    detail: str
    strong: bool
    source: str = "catalogo"
    rank: int | None = None


def worse(a: str, b: str) -> str:
    return a if VERDICT_ORDER.index(a) >= VERDICT_ORDER.index(b) else b


class LookalikeAnalyzer:
    YOUNG_DAYS = 90
    OLD_DAYS = 5 * 365

    def __init__(
        self,
        fetcher: HttpFetcher,
        catalog: BrandCatalog | None = None,
        confusables: Confusables | None = None,
        age_lookup: DomainAgeLookup | None = None,
        tranco: TrancoIndex | None | bool = True,
    ):
        self.fetcher = fetcher
        self.catalog = catalog or BrandCatalog()
        self.confusables = confusables or Confusables()
        self.age_lookup = age_lookup or DomainAgeLookup(fetcher)
        self.claims = BrandClaimVerifier(fetcher, self.catalog)
        self.tranco = load_tranco() if tranco is True else (tranco or None)

    # ------------------------------------------------------------------ #
    def analyze(self, domain: str, final_host: str | None = None, cert: dict | None = None,
                html: str | None = None) -> LookalikeResult:
        parts = split_domain(domain)
        label = to_unicode(parts.name).lower()
        idn = self.confusables.inspect(label)
        created, age_days, age_source = self.age_lookup.lookup(parts.registrable)

        result = LookalikeResult(
            domain=domain,
            display=to_unicode(domain),
            registrable=parts.registrable,
            skeleton=self.confusables.skeleton(label),
            scripts=idn.scripts,
            confusables=[asdict(c) for c in idn.confusables],
            age_days=age_days,
            created=created,
            age_source=age_source,
            tranco_rank=self.tranco.rank_of(parts.registrable) if self.tranco else None,
            sources=self._sources(),
        )

        official_brand = self.catalog.brand_of(parts.registrable)
        if official_brand:
            result.verdict, result.brand, result.target = "UFFICIALE", official_brand, parts.registrable
            result.reasons.append(f"{parts.registrable} e' nel catalogo dei domini ufficiali di {official_brand}.")
            self._popularity_reason(result)
            result.description = DESCRIPTIONS["UFFICIALE"].format(brand=official_brand)
            return result

        self._idn_reasons(idn, result)
        match = self._best_match(parts, label, idn, result.tranco_rank)
        if match is None:
            self._judge_without_match(idn, result)
        else:
            self._judge_match(match, parts, final_host, cert, result)

        if html:
            final_reg = split_domain(final_host).registrable if final_host else None
            claim = self.claims.verify(html, parts.registrable, final_reg)
            if claim:
                self._apply_claim(claim, parts, final_host, cert, result)

        self._apply_popularity(result)
        key = "SOSPETTO_NO_TARGET" if result.verdict == "SOSPETTO" and not result.target else result.verdict
        result.description = DESCRIPTIONS[key].format(brand=result.brand, target=result.target)
        return result

    def _sources(self) -> list[str]:
        sources = [f"Catalogo curato ({len(self.catalog)} domini ufficiali)"]
        if self.tranco:
            when = self.tranco.info.get("downloaded", "data sconosciuta")
            count = f"{len(self.tranco):,}".replace(",", ".")
            sources.append(f"Classifica Tranco ({count} siti piu' visitati, scaricata il {when})")
        else:
            sources.append("Classifica Tranco NON installata: esegui 'py scanner.py --update-tranco'")
        sources.append("Wikidata (sito ufficiale del marchio dichiarato dalla pagina)")
        return sources

    # ------------------------------------------------------------------ #
    @staticmethod
    def _idn_reasons(idn: IdnInfo, result: LookalikeResult) -> None:
        if idn.mixed:
            result.reasons.append(
                f"Il nome mescola alfabeti diversi ({', '.join(idn.scripts)}): e' la tecnica tipica degli omografi.")
        if idn.confusables:
            chars = ", ".join(f"'{c.char}' ({c.codepoint}, {c.name.title()}) sembra '{c.looks_like}'"
                              for c in idn.confusables)
            result.reasons.append(f"Contiene caratteri identici a lettere latine ma di altri alfabeti: {chars}.")

    def _judge_without_match(self, idn: IdnInfo, result: LookalikeResult) -> None:
        if idn.mixed or idn.confusables:
            result.verdict = "SOSPETTO"
        else:
            result.verdict = "NON SOSPETTO"
            checked = "nel catalogo e tra i siti piu' visitati" if self.tranco else "nel catalogo"
            result.reasons.append(f"Il nome del dominio non somiglia a nessun dominio noto {checked}.")
        if result.age_days is not None and result.age_days < self.YOUNG_DAYS:
            result.reasons.append(f"Il dominio esiste da soli {result.age_days} giorni: i domini di phishing "
                                  "sono quasi sempre registrati da poco.")

    def _judge_match(self, match: Match, parts: DomainParts, final_host: str | None,
                     cert: dict | None, result: LookalikeResult) -> None:
        result.brand, result.target, result.technique = match.brand, match.target, match.technique
        result.match_source, result.target_rank = match.source, match.rank
        result.reasons.append(match.detail)

        officials = self._officials_for(match)
        strong_proof, redirect_proof = self._ownership_evidence(parts, officials, match.brand, final_host, cert)
        age = result.age_days
        long_lived = age is not None and age >= self.OLD_DAYS
        if strong_proof or (redirect_proof and (not match.strong or long_lived)):
            result.verdict = "LEGITTIMO"
            result.reasons += strong_proof + redirect_proof
            if not strong_proof and long_lived:
                result.reasons.append(f"Registrato da {age // 365} anni e rimanda al sito ufficiale: e' una "
                                      "registrazione difensiva, i domini di phishing non durano cosi' a lungo.")
            return

        verdict = "LOOKALIKE" if match.strong else "SOSPETTO"
        if redirect_proof:
            verdict = "SOSPETTO"
            result.reasons += redirect_proof
            result.reasons.append("Alcuni kit di phishing reindirizzano al sito vero per eludere i controlli: "
                                  "il solo redirect non basta a dimostrare la legittimita'.")

        if age is not None and age < self.YOUNG_DAYS:
            if verdict == "SOSPETTO":
                verdict = "LOOKALIKE"
            result.reasons.append(f"Registrato da soli {age} giorni: insieme alla somiglianza con {match.target} "
                                  "e' un segnale forte di dominio creato per una campagna di phishing.")
        elif long_lived and match.technique not in (TECH_IDN, TECH_SUBDOMAIN):
            years = age // 365
            if verdict == "LOOKALIKE":
                verdict = "SOSPETTO"
                result.reasons.append(f"Registrato da {years} anni: i domini di phishing hanno vita breve, "
                                      "quindi il rischio e' attenuato.")
            elif not match.strong:
                verdict = "NON SOSPETTO"
                result.reasons.append(f"Registrato da {years} anni e senza parole tipiche del phishing: "
                                      "probabilmente e' un sito indipendente con un nome simile.")
        result.verdict = verdict

    def _apply_claim(self, claim: BrandClaim, parts: DomainParts, final_host: str | None,
                     cert: dict | None, result: LookalikeResult) -> None:
        """Confronta il marchio che la pagina dichiara con il suo sito ufficiale."""
        result.page_claim = asdict(claim)
        source = f"{claim.source}: \"{claim.name}\""
        officials = ", ".join(claim.official_domains[:4])

        if claim.status == "ufficiale":
            if parts.registrable in claim.official_domains:
                result.verdict = "UFFICIALE"
                result.brand, result.target, result.technique = claim.brand, parts.registrable, None
                result.reasons.append(f"La pagina si presenta come {claim.brand} ({source}) e secondo "
                                      f"{claim.verified_by} {parts.registrable} e' il suo sito ufficiale.")
            else:
                result.reasons.append(f"La pagina che si apre appartiene al sito ufficiale di {claim.brand} "
                                      f"({officials}) secondo {claim.verified_by}.")
            return

        if claim.status == "coerente":
            result.reasons.append(f"La pagina si presenta come \"{claim.name}\" ({claim.source}), "
                                  "coerente con il nome del dominio.")
            return

        if claim.status == "sconosciuto":
            if claim.lookup_failed:
                result.reasons.append(f"La pagina si presenta come \"{claim.name}\", ma Wikidata non ha risposto: "
                                      "verifica del marchio dichiarato incompleta.")
            return

        # non_corrispondente: la pagina dice di essere un marchio il cui sito ufficiale e' un altro
        strong_proof, redirect_proof = self._ownership_evidence(
            parts, set(claim.official_domains), claim.brand, final_host, cert)
        if strong_proof:
            result.reasons.append(f"La pagina si presenta come {claim.brand}, il cui sito ufficiale e' "
                                  f"{officials}: il dominio risulta collegato.")
            result.reasons += strong_proof
            if result.verdict in ("NON SOSPETTO", "SOSPETTO"):
                result.verdict, result.brand, result.target = "LEGITTIMO", claim.brand, claim.official_domains[0]
            return

        reliable = claim.source != "titolo" or claim.has_password
        login = " e contiene un modulo che chiede la password" if claim.has_password else ""
        result.reasons.append(f"La pagina si presenta come {claim.brand} ({source}){login}, ma il sito "
                              f"ufficiale di {claim.brand} secondo {claim.verified_by} e' {officials}, "
                              f"non {parts.registrable}.")
        if not reliable:
            result.reasons.append("Il nome compare solo nel titolo di una pagina senza login: "
                                  "potrebbe essere un sito che parla del marchio, non che lo imita.")
            return

        # somiglianza + identita' falsa, oppure identita' falsa con login: quasi certamente phishing
        escalated = "LOOKALIKE" if claim.has_password or result.verdict in ("SOSPETTO", "LOOKALIKE") else "SOSPETTO"
        if not result.target:
            # nessuna somiglianza nel nome: l'impersonificazione e' la prova principale
            result.brand, result.target = claim.brand, claim.official_domains[0]
            result.technique = TECH_IMPERSONATION
        result.verdict = worse(result.verdict, escalated)

    def _apply_popularity(self, result: LookalikeResult) -> None:
        """I domini tra i piu' visitati al mondo non sono siti di phishing usa-e-getta."""
        self._popularity_reason(result)
        rank = result.tranco_rank
        if rank is None or rank > POPULAR_RANK or result.technique in (TECH_IDN, TECH_SUBDOMAIN):
            return
        if result.verdict == "LOOKALIKE":
            result.verdict = "SOSPETTO"
            result.reasons.append("Essendo tra i siti piu' visitati, il verdetto e' attenuato a SOSPETTO.")
        elif result.verdict == "SOSPETTO":
            result.verdict = "NON SOSPETTO"
            result.reasons.append("Essendo tra i siti piu' visitati, la somiglianza e' probabilmente casuale.")

    @staticmethod
    def _popularity_reason(result: LookalikeResult) -> None:
        if result.tranco_rank is not None:
            rank = f"{result.tranco_rank:,}".replace(",", ".")
            result.reasons.append(f"E' alla posizione {rank} della classifica dei siti piu' visitati al mondo (Tranco).")

    # ------------------------------------------------------------------ #
    def _best_match(self, parts: DomainParts, label: str, idn: IdnInfo, own_rank: int | None) -> Match | None:
        sub_match = self._subdomain_match(parts)
        if sub_match:
            return sub_match
        skel = self.confusables.skeleton(label)
        best = None
        for bname, (brand, official) in self.catalog.names.items():
            m = self._compare(label, skel, bname, brand, official, parts, idn)
            if m and (best is None or PRIORITY.index(m.technique) < PRIORITY.index(best.technique)):
                best = m
        if best or not self.tranco or own_rank is not None:
            # se il dominio e' a sua volta tra i piu' visitati non lo confrontiamo con gli altri
            return best
        return self._tranco_match(parts, label, skel, idn)

    def _subdomain_match(self, parts: DomainParts) -> Match | None:
        if not parts.subdomain:
            return None
        sub = ".".join(parts.subdomain)
        for official, brand in self.catalog.official.items():
            oname = split_domain(official).name
            if official in sub or (len(oname) >= 5 and oname in parts.subdomain):
                return Match(
                    brand, official, TECH_SUBDOMAIN,
                    f"'{official}' compare nella parte iniziale dell'indirizzo, ma il dominio reale e' "
                    f"{parts.registrable}: chi legge di fretta crede di essere su {official}.",
                    strong=True,
                )
        return None

    def _compare(self, label: str, skel: str, bname: str, brand: str, official: str,
                 parts: DomainParts, idn: IdnInfo) -> Match | None:
        if label == bname:
            if len(bname) >= 5:
                return Match(brand, official, TECH_TLD,
                             f"Usa lo stesso nome di {official} ma con l'estensione .{parts.suffix}, "
                             f"che non risulta tra quelle ufficiali di {brand}.", strong=False)
            return None

        bskel = self.confusables.skeleton(bname)
        if len(bname) >= 3 and skel == bskel:
            return Match(brand, official, self._visual_technique(label, bname, idn),
                         f"'{label}' appare quasi identico a '{bname}' ({describe_diff(label, bname)}).",
                         strong=True)

        if len(bname) < 5:
            return None

        distance = min(osa_distance(label, bname), osa_distance(skel, bskel))
        if distance != 1 and (bname in label.split("-") or label.startswith(bname) or skel.startswith(bskel)):
            words = self._suspicious_words(label, bname)
            detail = f"Contiene il nome '{bname}' con parole aggiunte"
            detail += f" tipiche del phishing ({', '.join(words)})" if words else ""
            return Match(brand, official, TECH_COMBO, detail + f": puo' sembrare un sito di {brand}.",
                         strong=bool(words))

        if distance == 1:
            return Match(brand, official, TECH_TYPO,
                         f"Differisce da '{bname}' per un solo carattere ({describe_diff(label, bname)}): "
                         "sfrutta gli errori di battitura e le letture distratte.",
                         strong=len(bname) >= 6)
        if distance == 2 and len(bname) >= 8:
            return Match(brand, official, TECH_TYPO,
                         f"Differisce da '{bname}' per due caratteri ({describe_diff(label, bname)}).",
                         strong=False)
        return None

    def _tranco_match(self, parts: DomainParts, label: str, skel: str, idn: IdnInfo) -> Match | None:
        """Confronto con i 100.000 siti piu' visitati: copre i marchi che non sono nel catalogo."""
        t = self.tranco

        def popular(hit: TrancoHit) -> str:
            rank = f"{hit.rank:,}".replace(",", ".")
            return f"{hit.domain}, n. {rank} tra i siti piu' visitati"

        def make(hit: TrancoHit, technique: str, detail: str, strong: bool) -> Match:
            return Match(hit.domain, hit.domain, technique, detail, strong, source="Tranco", rank=hit.rank)

        if parts.subdomain:
            hit = t.subdomain_match(parts.subdomain)
            if hit and hit.domain != parts.registrable:
                return make(hit, TECH_SUBDOMAIN,
                            f"'{hit.domain}' ({popular(hit)}) compare nella parte iniziale dell'indirizzo, "
                            f"ma il dominio reale e' {parts.registrable}.", strong=hit.rank <= TRANCO_STRONG_RANK)

        hit = t.skeleton_match(label, skel)
        if hit:
            hname = split_domain(hit.domain).name
            return make(hit, self._visual_technique(label, hname, idn),
                        f"'{label}' appare quasi identico a '{hname}' ({popular(hit)}; "
                        f"{describe_diff(label, hname)}).", strong=hit.rank <= TRANCO_STRONG_RANK)

        if label.isascii():
            hit = t.typo_match(label)
            if hit:
                hname = split_domain(hit.domain).name
                return make(hit, TECH_TYPO,
                            f"Differisce da '{hname}' ({popular(hit)}) per un solo carattere "
                            f"({describe_diff(label, hname)}).",
                            strong=hit.rank <= TRANCO_TYPO_STRONG_RANK and len(hname) >= 7)

            hit = t.combo_match(label)
            if hit:
                hname = split_domain(hit.domain).name
                words = self._suspicious_words(label, hname)
                if words or hit.rank <= TRANCO_STRONG_RANK:
                    detail = f"Contiene il nome '{hname}' ({popular(hit)}) con parole aggiunte"
                    detail += f" tipiche del phishing ({', '.join(words)})" if words else ""
                    return make(hit, TECH_COMBO, detail + ".", strong=bool(words) and hit.rank <= TRANCO_STRONG_RANK)

            same = t.by_name.get(label)
            if same and same.domain != parts.registrable and same.rank <= TRANCO_TLD_RANK:
                return make(same, TECH_TLD,
                            f"Usa lo stesso nome di {popular(same)}, ma con l'estensione .{parts.suffix}.",
                            strong=False)
        return None

    @staticmethod
    def _visual_technique(label: str, original: str, idn: IdnInfo) -> str:
        if idn.non_ascii:
            return TECH_IDN
        if label.replace("-", "") == original:
            return TECH_HYPHEN
        return TECH_CHARS

    @staticmethod
    def _suspicious_words(label: str, brand_name: str) -> list[str]:
        rest = label.replace(brand_name, " ")
        return [w for w in SUSPICIOUS_WORDS if w in rest]

    # ------------------------------------------------------------------ #
    def _officials_for(self, match: Match) -> set[str]:
        if match.source == "catalogo":
            return set(self.catalog.official_domains(match.brand))
        return {match.target}

    def _ownership_evidence(self, parts: DomainParts, officials: set[str], brand: str,
                            final_host: str | None, cert: dict | None) -> tuple[list[str], list[str]]:
        """Prove che il dominio appartenga al proprietario del marchio: (prove forti, prova da redirect)."""
        strong: list[str] = []
        redirect: list[str] = []

        if final_host:
            final = split_domain(final_host).registrable
            if final in officials and final != parts.registrable:
                redirect.append(f"Il sito reindirizza al dominio ufficiale {final}.")

        if cert:
            sans = {v.lstrip("*.").lower() for k, v in cert.get("subjectAltName", ()) if k == "DNS"}
            shared = sorted({split_domain(s).registrable for s in sans} & officials)
            if shared:
                strong.append(f"Il certificato TLS e' lo stesso del dominio ufficiale {shared[0]}: "
                              "e' stato emesso per lo stesso proprietario.")

        ns_owner = sorted({split_domain(ns).registrable for ns in self._nameservers(parts.registrable)} & officials)
        if ns_owner:
            strong.append(f"I nameserver DNS appartengono a {ns_owner[0]}: il dominio e' gestito da {brand}.")
        return strong, redirect

    def _nameservers(self, domain: str) -> list[str]:
        if not HAS_DNS:
            return []
        try:
            answer = dns.resolver.resolve(domain, "NS", lifetime=self.fetcher.timeout)
            return [str(r.target).rstrip(".").lower() for r in answer]
        except Exception:
            return []
