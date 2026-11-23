"""Caratteri ingannevoli (omoglifi) e calcolo dello 'scheletro' visivo di un nome."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

# Caratteri di altri alfabeti visivamente identici (o quasi) a lettere latine.
# Scritti come escape per non confondere chi legge il codice.
CONFUSABLES: dict[str, str] = {
    # Cirillico
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "і": "i", "ї": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "к": "k",
    # Greco
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i",
    "κ": "k", "ν": "v", "υ": "u", "χ": "x", "ϲ": "c",
    "ω": "w", "τ": "t",
    # Armeno
    "օ": "o", "ս": "u", "ց": "g", "ո": "n", "հ": "h",
    # Latino esteso / IPA (non si scompongono con NFKD)
    "ı": "i", "ɡ": "g", "ɑ": "a", "ł": "l", "ø": "o",
    "đ": "d", "ħ": "h",
}

# Sostituzioni ASCII che ingannano l'occhio. Applicate allo stesso modo al nome
# analizzato e ai nomi dei marchi, cosi' il confronto e' simmetrico.
MULTI_CHAR = [("rn", "m"), ("vv", "w")]
SINGLE_CHAR = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "4": "a", "-": None})


@dataclass
class ConfusableChar:
    char: str
    codepoint: str
    name: str
    looks_like: str


@dataclass
class IdnInfo:
    """Caratteristiche Unicode di un'etichetta di dominio."""

    non_ascii: bool
    scripts: list[str] = field(default_factory=list)
    confusables: list[ConfusableChar] = field(default_factory=list)

    @property
    def mixed(self) -> bool:
        return len(self.scripts) > 1


class Confusables:
    """Riconosce gli omoglifi e riduce un nome alla sua forma visiva essenziale."""

    @staticmethod
    def _strip_accents(ch: str) -> str:
        decomposed = unicodedata.normalize("NFKD", ch)
        return "".join(c for c in decomposed if not unicodedata.combining(c))

    @staticmethod
    def script_of(ch: str) -> str:
        name = unicodedata.name(ch, "")
        return name.split(" ")[0] if name else "SCONOSCIUTO"

    def skeleton(self, label: str) -> str:
        """
        Forma 'come appare a occhio': 'pаypa1' (а cirillica, 1 al posto di l) e 'paypal'
        hanno lo stesso scheletro.
        """
        text = unicodedata.normalize("NFKC", label.lower())
        out = "".join(self._strip_accents(CONFUSABLES.get(ch, ch)) for ch in text)
        for seq, repl in MULTI_CHAR:
            out = out.replace(seq, repl)
        return out.translate(SINGLE_CHAR)

    def inspect(self, label: str) -> IdnInfo:
        letters = [c for c in label if c.isalpha()]
        info = IdnInfo(
            non_ascii=any(ord(c) > 127 for c in label),
            scripts=sorted({self.script_of(c) for c in letters}),
        )
        seen = set()
        for ch in label:
            if ch in CONFUSABLES and ch not in seen:
                seen.add(ch)
                info.confusables.append(ConfusableChar(
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=unicodedata.name(ch, "?"),
                    looks_like=CONFUSABLES[ch],
                ))
        return info
