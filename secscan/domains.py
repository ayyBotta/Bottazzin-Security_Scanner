"""Scomposizione dei nomi di dominio (sottodominio, nome, suffisso)."""

from __future__ import annotations

from dataclasses import dataclass

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "com.br", "co.jp", "co.in", "co.nz",
    "com.mx", "com.cn", "com.tr", "com.tw", "com.hk", "com.sg", "com.ar", "co.za", "co.kr",
    "com.pl", "com.ua", "com.es", "gov.it", "edu.it",
}


@dataclass
class DomainParts:
    """'login.paypal.co.uk' -> subdomain=['login'], name='paypal', suffix='co.uk'."""

    subdomain: list[str]
    name: str
    suffix: str

    @property
    def registrable(self) -> str:
        return f"{self.name}.{self.suffix}" if self.suffix else self.name


def split_domain(domain: str) -> DomainParts:
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return DomainParts([], labels[0] if labels else "", "")
    suffix_len = 2 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    return DomainParts(
        subdomain=labels[:-(suffix_len + 1)],
        name=labels[-(suffix_len + 1)],
        suffix=".".join(labels[-suffix_len:]),
    )
