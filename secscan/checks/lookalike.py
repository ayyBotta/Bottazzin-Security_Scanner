"""Controlli sulla legittimita' del dominio: omografi e lookalike."""

from __future__ import annotations

from ..antibot import blocked_message
from ..fetcher import HttpFetcher
from ..lookalike import LookalikeAnalyzer
from ..models import Check, LookalikeResult, ScanContext, Severity, Skip
from .base import BaseChecker


class LookalikeChecker(BaseChecker):
    """Trasforma il verdetto del LookalikeAnalyzer in controlli con punteggio."""

    category = "Lookalike"
    CAPS = {"LOOKALIKE": 15, "SOSPETTO": 50}
    SIMILARITY_POINTS = {"UFFICIALE": 10, "LEGITTIMO": 10, "NON SOSPETTO": 10, "SOSPETTO": 4, "LOOKALIKE": 0}

    def __init__(self, fetcher: HttpFetcher):
        super().__init__(fetcher)
        self.analyzer = LookalikeAnalyzer(fetcher)

    def run(self, ctx: ScanContext) -> list[Check]:
        res = self.analyzer.analyze(ctx.domain, final_host=ctx.final_host, cert=ctx.cert, html=self._html(ctx))
        ctx.lookalike = res
        if res.verdict in self.CAPS:
            target = f" che imita {res.target}" if res.target else ""
            ctx.add_cap(self.CAPS[res.verdict], f"Dominio {res.verdict.lower()}{target}")
        return [self._idn(res), self._similarity(res), self._claim(res, ctx), self._age(res)]

    @staticmethod
    def _html(ctx: ScanContext) -> str | None:
        resp = ctx.main_response
        if ctx.bot_block:
            return None  # pagina del firewall: non dichiara il marchio del sito
        if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
            return None
        try:
            return resp.text
        except Exception:
            return None

    def _claim(self, res: LookalikeResult, ctx: ScanContext) -> Check:
        c = self.check("Identita' dichiarata dalla pagina", 5, Severity.CRITICA,
                       "Una pagina che si presenta con il nome di un marchio (titolo, nome del sito, modulo di "
                       "login) ma non e' ospitata su un suo dominio ufficiale e' il segno distintivo del phishing.")
        claim = res.page_claim
        if res.verdict == "UFFICIALE" and not claim:
            c.points, c.message = 5, "Dominio ufficiale: verifica non necessaria"
            return c
        if not claim:
            if ctx.bot_block:
                c.skip(blocked_message(ctx.bot_block), Skip.BOT_BLOCK)
            else:
                c.skip("La pagina non dichiara un nome riconoscibile", Skip.NO_BRAND)
            return c
        status = claim["status"]
        if status == "ufficiale":
            c.points, c.message = 5, f"\"{claim['name']}\": sito ufficiale secondo {claim['verified_by']}"
        elif status == "coerente":
            c.points, c.message = 5, f"\"{claim['name']}\": coerente con il nome del dominio"
        elif status == "non_corrispondente":
            officials = ", ".join(claim["official_domains"][:3])
            c.message = f"Si presenta come {claim['brand']}, ma il sito ufficiale e' {officials}"
            if claim["source"] == "titolo" and not claim["has_password"]:
                c.points = 3  # marchio solo nel titolo e nessun login: puo' essere un sito che ne parla
        elif claim["lookup_failed"]:
            c.skip(f"\"{claim['name']}\": Wikidata non raggiungibile", Skip.WIKIDATA)
        else:
            c.points, c.message = 5, f"\"{claim['name']}\": nessun marchio noto con questo nome"
        return c

    def _idn(self, res: LookalikeResult) -> Check:
        c = self.check("Caratteri ingannevoli (IDN)", 5, Severity.CRITICA,
                       "Lettere di altri alfabeti (es. la 'а' cirillica) sono identiche a quelle latine: un "
                       "dominio come 'pаypal.com' sembra quello vero ma porta su un server diverso "
                       "(attacco omografo IDN).")
        if res.confusables:
            c.message = "Caratteri di altri alfabeti: " + ", ".join(
                f"{x['char']} ({x['codepoint']}) sembra '{x['looks_like']}'" for x in res.confusables)
        elif len(res.scripts) > 1:
            c.message = f"Alfabeti misti nel nome: {', '.join(res.scripts)}"
        elif res.display != res.domain:
            c.points = 5 if res.scripts and res.scripts != ["LATIN"] else 4
            c.message = f"Dominio internazionalizzato ({res.display}) senza caratteri ingannevoli"
        else:
            c.points, c.message = 5, "Solo caratteri ASCII standard"
        return c

    def _similarity(self, res: LookalikeResult) -> Check:
        c = self.check("Somiglianza con domini noti", 10, Severity.CRITICA,
                       "Un dominio che imita quello di un marchio noto (typosquatting, omografi, parole "
                       "aggiunte) serve quasi sempre a rubare credenziali o dati di pagamento con il phishing.")
        c.points = self.SIMILARITY_POINTS[res.verdict]
        if res.verdict in ("SOSPETTO", "LOOKALIKE") and res.target:
            rank = f", n. {res.target_rank} tra i siti piu' visitati" if res.target_rank else ""
            c.message = f"{res.verdict}: imita {res.target} ({res.technique}{rank})"
        elif res.verdict in ("UFFICIALE", "LEGITTIMO"):
            c.message = f"{res.verdict}: dominio di {res.brand}"
        else:
            c.message = res.verdict
        return c

    def _age(self, res: LookalikeResult) -> Check:
        c = self.check("Eta' del dominio", 5, Severity.ALTA,
                       "I domini di phishing vengono registrati pochi giorni prima dell'attacco e abbandonati "
                       "subito dopo: un dominio appena nato e' un forte segnale di rischio.")
        if res.age_days is None:
            c.skip("Data di registrazione non disponibile (RDAP/WHOIS)", Skip.NO_AGE)
            return c
        days = res.age_days
        c.points = 5 if days >= 365 else 4 if days >= 180 else 3 if days >= 90 else 1 if days >= 30 else 0
        age = f"{days // 365} anni" if days >= 365 else f"{days} giorni"
        c.message = f"Registrato il {res.created} ({age} fa, fonte {res.age_source})"
        return c
