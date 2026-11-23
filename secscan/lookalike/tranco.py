"""
Classifica Tranco (https://tranco-list.eu): il milione di domini piu' visitati al mondo.

Ne teniamo i primi 100.000 e li indicizziamo per trovare in pochi millisecondi:
  - domini con lo stesso 'scheletro' visivo (omografi, 0/o, 1/l, rn/m...)
  - domini a distanza di un carattere (typosquatting)
  - domini contenuti nel nome o nel sottodominio (combosquatting)
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from ..fetcher import HttpFetcher
from .similarity import osa_distance
from .brands import split_domain
from .confusables import Confusables

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "tranco"
LIST_FILE = DATA_DIR / "top-100k.csv"
INFO_FILE = DATA_DIR / "info.json"
DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"
KEEP = 100_000

HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")


@dataclass
class TrancoHit:
    domain: str
    rank: int


class TrancoIndex:
    """Indici costruiti sulla classifica per le ricerche di somiglianza."""

    SKELETON_MIN_LEN = 4
    TYPO_TOP = 30_000       # solo i piu' popolari: e' li' che si concentra il typosquatting
    TYPO_MIN_LEN = 6
    COMBO_TOP = 20_000
    COMBO_MIN_LEN = 5

    def __init__(self, entries: list[tuple[int, str]], info: dict | None = None):
        self.info = info or {}
        self.rank: dict[str, int] = {}
        self.by_name: dict[str, TrancoHit] = {}
        self.by_skeleton: dict[str, TrancoHit] = {}
        self.combo_names: dict[str, TrancoHit] = {}
        self.typo_names: dict[str, TrancoHit] = {}
        self.deletes: dict[str, list[str]] = {}
        confusables = Confusables()

        for rank, domain in entries:
            self.rank.setdefault(domain, rank)
            name = split_domain(domain).name
            hit = TrancoHit(domain, rank)
            if name in self.by_name:
                continue  # stesso nome con altra estensione: vale il piu' popolare
            self.by_name[name] = hit
            if len(name) >= self.SKELETON_MIN_LEN:
                self.by_skeleton.setdefault(confusables.skeleton(name), hit)
            if rank <= self.COMBO_TOP and len(name) >= self.COMBO_MIN_LEN:
                self.combo_names[name] = hit
            if rank <= self.TYPO_TOP and len(name) >= self.TYPO_MIN_LEN:
                self.typo_names[name] = hit
                for variant in self._deletions(name):
                    self.deletes.setdefault(variant, []).append(name)

    def __len__(self) -> int:
        return len(self.rank)

    @staticmethod
    def _deletions(word: str) -> set[str]:
        return {word[:i] + word[i + 1:] for i in range(len(word))}

    # --- ricerche --------------------------------------------------------- #
    def rank_of(self, registrable: str) -> int | None:
        return self.rank.get(registrable)

    def skeleton_match(self, name: str, skeleton: str) -> TrancoHit | None:
        hit = self.by_skeleton.get(skeleton)
        return hit if hit and split_domain(hit.domain).name != name else None

    def typo_match(self, name: str) -> TrancoHit | None:
        """Nomi popolari a distanza 1 (lettera mancante, in piu', sostituita o invertita)."""
        candidates: set[str] = set()
        variants = self._deletions(name)
        candidates.update(v for v in variants if v in self.typo_names)       # lettera in piu'
        candidates.update(self.deletes.get(name, []))                          # lettera mancante
        for v in variants:                                                     # sostituita / invertita
            candidates.update(self.deletes.get(v, []))
        candidates.discard(name)
        hits = [self.typo_names[c] for c in candidates if osa_distance(name, c) == 1]
        return min(hits, key=lambda h: h.rank) if hits else None

    def combo_match(self, label: str) -> TrancoHit | None:
        """Nome popolare usato come parola del dominio ('paypal-login') o come prefisso."""
        hits = [self.combo_names[t] for t in label.split("-") if t in self.combo_names and t != label]
        for k in range(len(label) - 1, self.COMBO_MIN_LEN - 1, -1):
            prefix = label[:k]
            if prefix in self.combo_names:
                hits.append(self.combo_names[prefix])
                break
        return min(hits, key=lambda h: h.rank) if hits else None

    def subdomain_match(self, subdomain: list[str]) -> TrancoHit | None:
        """'paypal.com.verifica.net': un dominio popolare scritto dentro il sottodominio."""
        hits = []
        for size in (2, 3):
            for i in range(len(subdomain) - size + 1):
                candidate = ".".join(subdomain[i:i + size])
                if candidate in self.rank and self.rank[candidate] <= self.COMBO_TOP:
                    hits.append(TrancoHit(candidate, self.rank[candidate]))
        hits += [self.combo_names[label] for label in subdomain if label in self.combo_names]
        return min(hits, key=lambda h: h.rank) if hits else None


class TrancoList:
    """Download, salvataggio e caricamento della classifica."""

    @staticmethod
    def update(fetcher: HttpFetcher, keep: int = KEEP) -> dict:
        resp = fetcher.get(DOWNLOAD_URL, timeout=120)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as archive:
            csv_name = next(n for n in archive.namelist() if n.endswith(".csv"))
            with archive.open(csv_name) as raw:
                rows = TrancoList._parse(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"), keep)
        if len(rows) < 1000:
            raise ValueError("La lista scaricata non sembra una classifica Tranco valida.")

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with LIST_FILE.open("w", encoding="utf-8", newline="") as out:
            csv.writer(out).writerows(rows)
        info = {
            "source": DOWNLOAD_URL,
            "downloaded": datetime.now(timezone.utc).date().isoformat(),
            "domains": len(rows),
        }
        INFO_FILE.write_text(json.dumps(info, indent=2), encoding="utf-8")
        load_tranco.cache_clear()
        return info

    @staticmethod
    def _parse(lines, keep: int) -> list[tuple[int, str]]:
        """Legge 'rank,dominio' scartando le righe malformate (il file e' dato esterno)."""
        rows = []
        for row in csv.reader(lines):
            if len(rows) >= keep:
                break
            if len(row) != 2 or not row[0].isdigit():
                continue
            domain = row[1].strip().lower()
            if HOST_RE.match(domain):
                rows.append((int(row[0]), domain))
        return rows


@lru_cache(maxsize=1)
def load_tranco() -> TrancoIndex | None:
    """Carica (una volta sola per processo) l'indice, o None se la lista non e' installata."""
    if not LIST_FILE.exists():
        return None
    with LIST_FILE.open(encoding="utf-8") as f:
        rows = TrancoList._parse(f, KEEP)
    info = json.loads(INFO_FILE.read_text(encoding="utf-8")) if INFO_FILE.exists() else {}
    return TrancoIndex(rows, info)
