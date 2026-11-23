"""Funzioni di confronto tra stringhe usate da tutta l'analisi lookalike."""

from __future__ import annotations

import difflib
import re
import unicodedata


def osa_distance(a: str, b: str) -> int:
    """Distanza di Damerau-Levenshtein (variante OSA): conta anche due lettere invertite come 1."""
    if abs(len(a) - len(b)) > 2:
        return 3  # abbastanza per i nostri scopi, evita calcoli inutili
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def to_unicode(domain: str) -> str:
    """'xn--gthub-n4a.com' -> 'gіthub.com' (i cirillica)."""
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def describe_diff(seen: str, expected: str) -> str:
    """Descrive in italiano cosa cambia tra il nome visto e quello originale."""
    parts = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, seen, expected).get_opcodes():
        if tag == "replace":
            parts.append(f"'{seen[i1:i2]}' al posto di '{expected[j1:j2]}'")
        elif tag == "delete":
            parts.append(f"'{seen[i1:i2]}' in piu'")
        elif tag == "insert":
            parts.append(f"manca '{expected[j1:j2]}'")
    return ", ".join(parts) or "identico"


def compact(text: str) -> str:
    """'Poste Italiane S.p.A.' -> 'posteitalianespa': minuscolo, senza accenti, spazi e punteggiatura."""
    decomposed = unicodedata.normalize("NFKD", text.lower())
    no_accents = "".join(c for c in decomposed if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", no_accents)
