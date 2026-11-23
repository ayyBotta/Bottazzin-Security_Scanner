"""Verifica di legittimita': riconoscimento di domini omografi e lookalike."""

from .analyzer import LookalikeAnalyzer
from .brands import BRANDS, BrandCatalog, split_domain
from .confusables import Confusables
from .page_brand import BrandClaimVerifier, WikidataClient
from .similarity import osa_distance, to_unicode
from .tranco import TrancoIndex, TrancoList, load_tranco

__all__ = [
    "LookalikeAnalyzer", "BrandCatalog", "Confusables", "BRANDS", "split_domain",
    "BrandClaimVerifier", "WikidataClient", "TrancoIndex", "TrancoList", "load_tranco",
    "osa_distance", "to_unicode",
]
