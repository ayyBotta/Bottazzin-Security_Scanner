"""Orchestratore: raccoglie i dati, esegue i checker, calcola il punteggio di sicurezza."""

from __future__ import annotations

import re

from .checks import DEFAULT_CHECKERS, BaseChecker
from .fetcher import HttpFetcher
from .models import Check, LookalikeResult, ScanContext, ScanResult
from .lookalike import LookalikeAnalyzer
from .scorer import SecurityScorer


class DomainUnreachableError(Exception):
    """Il dominio non risponde; porta comunque con se' l'analisi lookalike (fatta senza rete HTTP)."""

    def __init__(self, message: str, lookalike: LookalikeResult | None = None):
        super().__init__(message)
        self.lookalike = lookalike


class SecurityScanner:
    def __init__(
        self,
        fetcher: HttpFetcher | None = None,
        checkers: list[type[BaseChecker]] | None = None,
        scorer: SecurityScorer | None = None,
    ):
        self.fetcher = fetcher or HttpFetcher()
        self.checkers = [cls(self.fetcher) for cls in (checkers or DEFAULT_CHECKERS)]
        self.scorer = scorer or SecurityScorer()

    @staticmethod
    def normalize(domain: str) -> str:
        """
        Accetta anche URL completi: 'https://Example.com/path' -> 'example.com'.
        I domini con caratteri Unicode vengono convertiti in punycode ('xn--...').
        """
        domain = re.sub(r"^https?://", "", domain.strip(), flags=re.I)
        domain = domain.split("/")[0].split(":")[0].strip(".").lower()
        try:
            return domain.encode("idna").decode("ascii")
        except UnicodeError:
            return domain

    def scan(self, domain: str, follow_redirect: bool = True) -> ScanResult:
        ctx = ScanContext(domain=self.normalize(domain))
        self.fetcher.collect(ctx)
        if not ctx.reachable:
            analysis = LookalikeAnalyzer(self.fetcher).analyze(ctx.domain)
            raise DomainUnreachableError(
                f"Impossibile raggiungere {analysis.display} ne' in HTTP ne' in HTTPS.", lookalike=analysis)

        checks: list[Check] = []
        for checker in self.checkers:
            checks.extend(checker.run(ctx))

        score = self.scorer.compute(checks, ctx.caps)
        result = ScanResult(
            domain=ctx.domain,
            score=score,
            level=self.scorer.qualify(score),
            checks=checks,
            caps=ctx.caps,
            lookalike=ctx.lookalike,
            redirect_target=ctx.redirect_target,
            bot_block=ctx.bot_block,
            chains={label: [(h.status_code, h.url) for h in [*resp.history, resp]]
                    for label, resp in (("HTTPS", ctx.https_response), ("HTTP", ctx.http_response))
                    if resp is not None},
        )
        if ctx.redirect_target and follow_redirect:
            # punteggio separato della destinazione (un solo livello, niente catene infinite)
            try:
                result.destination = self.scan(ctx.redirect_target, follow_redirect=False)
            except DomainUnreachableError:
                result.destination = None
        return result
