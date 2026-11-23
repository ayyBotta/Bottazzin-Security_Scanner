"""Classe base per tutti i checker."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..fetcher import HttpFetcher
from ..models import Check, ScanContext, Severity


class BaseChecker(ABC):
    """Un checker analizza un aspetto del dominio e restituisce una lista di Check."""

    category: str = ""

    def __init__(self, fetcher: HttpFetcher):
        self.fetcher = fetcher
        self.timeout = fetcher.timeout

    def check(self, name: str, max_points: int, severity: Severity, why: str) -> Check:
        """Crea un Check gia' associato alla categoria del checker."""
        return Check(self.category, name, max_points, severity=severity, why=why)

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Check]:
        ...
