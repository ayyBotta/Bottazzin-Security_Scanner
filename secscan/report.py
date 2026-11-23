"""Formattazione dell'output: console e JSON."""

from __future__ import annotations

import json
import os
import sys
import textwrap
from dataclasses import asdict
from itertools import groupby

from .models import Check, LookalikeResult, ScanResult, Severity, SkipReason


class ConsoleReporter:
    """Report di sicurezza leggibile a terminale, con colori ANSI."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[90m"
    SEVERITY_COLORS = {
        Severity.CRITICA: "\033[95m",
        Severity.ALTA: "\033[91m",
        Severity.MEDIA: "\033[93m",
        Severity.BASSA: "\033[96m",
        Severity.INFO: "\033[90m",
    }
    LEVEL_COLORS = {
        "CRITICO": "\033[95m", "ALTO": "\033[91m", "ELEVATO": "\033[93m",
        "MODERATO": "\033[96m", "BASSO": "\033[92m",
    }
    VERDICT_COLORS = {
        "UFFICIALE": "[92m", "LEGITTIMO": "[92m", "NON SOSPETTO": "[96m",
        "SOSPETTO": "[93m", "LOOKALIKE": "[95m",
    }
    WIDTH = 78

    def __init__(self):
        if sys.platform == "win32":
            os.system("")  # abilita i colori ANSI nel terminale Windows
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # domini con caratteri Unicode

    def render(self, result: ScanResult) -> str:
        out: list[str] = []
        out += self._header(result)
        out += self._chains(result)
        out += self._redirect_notice(result)
        out += self._destination(result)      # in evidenza: il sito vero e' la destinazione
        out += self._bot_block_notice(result)
        if result.lookalike:
            out += self.lookalike_section(result.lookalike)
        out += self._findings(result)
        out += self._categories(result)
        out += self._passed_and_skipped(result)
        return "\n".join(out) + "\n"

    # --- sezioni ---------------------------------------------------------- #
    def _header(self, r: ScanResult) -> list[str]:
        color = self.LEVEL_COLORS.get(r.level.name, "")
        lines = [
            "",
            f"{self.BOLD}ANALISI DI SICUREZZA: {r.domain}{self.RESET}",
            "=" * self.WIDTH,
            f"  Punteggio di sicurezza: {self.BOLD}{color}{r.score}/100{self.RESET}"
            f"   Livello di rischio: {self.BOLD}{color}{r.level.name}{self.RESET}",
            *self._wrap(r.level.description, indent=2),
        ]
        for cap in r.caps:
            lines.append(f"  ! Punteggio limitato a {cap.max_score} per un problema critico: {cap.reason}")
        lines.append(f"{self.DIM}  (100 = sito sicuro, 0 = sito gravemente insicuro){self.RESET}")
        return lines

    @staticmethod
    def format_chain(chain: list[tuple[int, str]]) -> str:
        """https://zalando.com/ -> 302 -> https://www.zalando.it/ -> 403"""
        return " -> ".join(f"{url} -> {status}" for status, url in chain)

    def _chains(self, r: ScanResult) -> list[str]:
        shown = {label: chain for label, chain in r.chains.items() if len(chain) > 1}
        if not shown:
            return []
        lines = ["", f"  {self.BOLD}Catena dei redirect{self.RESET} {self.DIM}(header letti sulla risposta finale del dominio){self.RESET}"]
        for label, chain in shown.items():
            lines += textwrap.wrap(f"{label + ':':<7}{self.format_chain(chain)}", width=self.WIDTH,
                                   initial_indent="    ", subsequent_indent=" " * 11, break_on_hyphens=False)
        return lines

    def _redirect_notice(self, r: ScanResult) -> list[str]:
        if not r.redirect_target:
            return []
        lines = ["", f"  {self.BOLD}\033[96m-> {r.domain} e' solo un redirect verso {r.redirect_target}{self.RESET}"]
        lines += self._wrap(
            "Il punteggio qui sopra riguarda solo il redirect: HTTPS, HSTS, certificato, versioni TLS, primo "
            "salto da http:// a https://, cookie e banner della risposta di redirect. La risposta 3xx non ha "
            "contenuto, quindi CSP, clickjacking, nosniff, Referrer-Policy e Permissions-Policy sono 'non "
            "applicabili': nessuna penalita' e nessun punto. Il sito vero e' la destinazione qui sotto.",
            indent=5)
        return lines

    def _bot_block_notice(self, r: ScanResult) -> list[str]:
        if not r.bot_block:
            return []
        lines = ["", f"  {self.BOLD}\033[93m! Risultato non affidabile: richiesta bloccata ({r.bot_block}){self.RESET}"]
        lines += self._wrap(
            "Al posto della homepage e' arrivata una pagina di blocco o di errore (protezione anti-bot o "
            "risposta 401/403/429/5xx). I suoi header, cookie e banner non sono quelli del sito, quindi non "
            "vengono valutati e non danno punti: il punteggio si basa solo su cio' che si puo' verificare "
            "(HTTPS/TLS, certificato, legittimita', DNS/Email). La protezione anti-bot in se' non e' un "
            "problema di sicurezza.", indent=5)
        return lines

    def _destination(self, r: ScanResult) -> list[str]:
        if not r.redirect_target:
            return []
        lines = ["", f"  {self.BOLD}\033[96mSITO DI DESTINAZIONE: {r.redirect_target}{self.RESET}"]
        d = r.destination
        if d is None:
            lines.append("    Destinazione non raggiungibile: nessun punteggio.")
            return lines
        color = self.LEVEL_COLORS.get(d.level.name, "")
        lines.append(f"    Punteggio di sicurezza: {self.BOLD}{color}{d.score}/100{self.RESET}"
                     f"   Livello di rischio: {self.BOLD}{color}{d.level.name}{self.RESET}")
        if d.lookalike:
            lines.append(f"    Verifica di legittimita': {d.lookalike.verdict}")
        if d.bot_block:
            lines.append(f"    ! Risultato non affidabile: richiesta bloccata ({d.bot_block})")
        legacy = next((c for c in d.checks if c.name == "TLS 1.0/1.1 disabilitati"), None)
        if legacy:
            lines.append(f"    TLS 1.0/1.1: {legacy.message}")
        top = d.findings[:3]
        if top:
            lines.append("    Principali fattori di pericolosita':")
            for c in top:
                lines += self._wrap(f"- [{c.effective_severity.label}] {c.name}: {c.message}", indent=6)
        lines.append(f"    {self.BOLD}Analisi completa:{self.RESET} py scanner.py {d.domain}")
        return lines

    CLAIM_LABELS = {
        "ufficiale": "sito ufficiale confermato",
        "coerente": "coerente con il dominio",
        "non_corrispondente": "NON e' un suo dominio ufficiale",
        "sconosciuto": "marchio non trovato",
    }

    def lookalike_section(self, la: LookalikeResult) -> list[str]:
        color = self.VERDICT_COLORS.get(la.verdict, "")
        row = lambda label, value: f"  {label + ':':<14} {value}"
        lines = ["", f"{self.BOLD}VERIFICA DI LEGITTIMITA' (omografi / lookalike){self.RESET}", "-" * self.WIDTH,
                 f"  Verdetto: {self.BOLD}{color}{la.verdict}{self.RESET}"]
        lines += self._wrap(la.description, indent=2)
        lines.append("")
        domain = la.domain if la.display == la.domain else f"{la.display}   {self.DIM}(punycode: {la.domain}){self.RESET}"
        lines.append(row("Dominio", domain))
        if la.target and la.verdict != "UFFICIALE":
            label = {"LEGITTIMO": "Collegato a", "NON SOSPETTO": "Somiglia a"}.get(la.verdict, "Imita")
            brand = f" ({la.brand})" if la.brand and la.brand != la.target else ""
            lines.append(row(label, f"{la.target}{brand}"))
        if la.technique:
            lines.append(row("Tecnica", la.technique))
        if la.age_days is not None:
            age = f"{la.age_days // 365} anni" if la.age_days >= 365 else f"{la.age_days} giorni"
            lines.append(row("Eta'", f"{age} (registrato il {la.created}, fonte {la.age_source})"))
        else:
            lines.append(row("Eta'", f"{self.DIM}non disponibile{self.RESET}"))
        rank = f"n. {la.tranco_rank:,} al mondo".replace(",", ".") if la.tranco_rank else "fuori dai primi 100.000"
        lines.append(row("Popolarita'", rank))
        claim = la.page_claim
        if claim:
            status = self.CLAIM_LABELS.get(claim["status"], claim["status"])
            if claim.get("lookup_failed") and claim["status"] == "sconosciuto":
                status = "Wikidata non raggiungibile"
            lines.append(row("Si presenta", f"\"{claim['name']}\" ({claim['source']}) -> {status}"))
        if la.reasons:
            lines.append("  Perche':")
            for reason in la.reasons:
                lines += self._wrap(f"- {reason}", indent=4)
        if la.sources:
            lines.append(f"  {self.DIM}Fonti: " + "; ".join(la.sources) + self.RESET)
        return lines

    def _findings(self, r: ScanResult) -> list[str]:
        findings = r.findings
        lines = ["", f"{self.BOLD}FATTORI DI PERICOLOSITA' ({len(findings)}){self.RESET}  "
                     f"{self.DIM}ordinati per gravita' e impatto{self.RESET}", "-" * self.WIDTH]
        if not findings:
            lines.append("  Nessun fattore di pericolosita' rilevato.")
        for i, c in enumerate(findings, 1):
            sev = c.effective_severity
            lines.append(
                f"\n  {i:>2}. {self.SEVERITY_COLORS[sev]}[{sev.label}]{self.RESET} "
                f"{self.BOLD}{c.name}{self.RESET}  {self.DIM}({c.category}){self.RESET}"
                f"   -{c.lost_points:g} punti"
            )
            lines += self._wrap(f"Rilevato: {c.message}", indent=6)
            if c.source_url:
                lines += self._wrap(f"Rilevato su: {c.source_url}", indent=6)
            lines += self._wrap(f"Perche' e' pericoloso: {c.why}", indent=6)
        return lines

    def _categories(self, r: ScanResult) -> list[str]:
        lines = ["", f"{self.BOLD}SICUREZZA PER CATEGORIA{self.RESET}", "-" * self.WIDTH]
        for category, group in groupby(r.checks, key=lambda c: c.category):
            group = list(group)
            active = [c for c in group if not c.skipped]
            if not active:
                labels = ", ".join(dict.fromkeys(c.skip_reason.label for c in group if c.skip_reason))
                why = f" ({labels})" if labels else ""
                lines.append(f"  {category:<16} {self.DIM}non verificata{why}{self.RESET}")
                continue
            got = sum(c.points for c in active)
            tot = sum(c.max_points for c in active)
            pct = got / tot * 100 if tot else 100
            lines.append(f"  {category:<16} {pct:5.0f}%  {self._bar(pct, 100)}  {self.DIM}{got:g}/{tot}{self.RESET}")
        return lines

    def _passed_and_skipped(self, r: ScanResult) -> list[str]:
        passed = [c for c in r.checks if c.status == "OK"]
        skipped = [c for c in r.checks if c.skipped]
        lines = ["", f"{self.BOLD}CONTROLLI SUPERATI ({len(passed)}){self.RESET}", "-" * self.WIDTH]
        for c in passed:
            lines.append(f"  \033[92m+{self.RESET} {c.name:<34} {self.DIM}{c.message}{self.RESET}")
            if c.source_url and c.category == "Header":
                lines.append(f"    {' ' * 34} {self.DIM}su {c.source_url}{self.RESET}")
        if skipped:
            lines += ["", f"{self.BOLD}ESCLUSI DAL CALCOLO ({len(skipped)}){self.RESET}  "
                          f"{self.DIM}non contano nel punteggio, ne' a favore ne' contro{self.RESET}",
                      "-" * self.WIDTH]
            for reason, group in skipped_groups(skipped):
                lines.append("")
                if reason:
                    lines.append(f"  {self.BOLD}Motivo: {reason.label}{self.RESET}")
                    lines += textwrap.wrap(reason.text, width=self.WIDTH,
                                           initial_indent="  ", subsequent_indent="  ")
                messages = {c.message for c in group}
                if len(messages) == 1 and len(group) > 1:
                    # stesso dettaglio per tutti: una volta sola, poi solo i nomi
                    lines += self._wrap(f"{self.DIM}Su questo dominio: {group[0].message}{self.RESET}", indent=2)
                    lines += [f"    - {c.name}" for c in group]
                else:
                    lines += [f"    - {c.name:<34} {self.DIM}{c.message}{self.RESET}" for c in group]
        return lines

    # --- helper ----------------------------------------------------------- #
    def _wrap(self, text: str, indent: int) -> list[str]:
        return textwrap.wrap(text, width=self.WIDTH, initial_indent=" " * indent,
                             subsequent_indent=" " * (indent + 2))

    @staticmethod
    def _bar(value: float, maximum: float, width: int = 20) -> str:
        filled = round(width * value / maximum) if maximum else 0
        return "[" + "#" * filled + "." * (width - filled) + "]"


def skipped_groups(skipped: list[Check]) -> list[tuple[SkipReason | None, list[Check]]]:
    """Controlli esclusi raggruppati per motivo, nell'ordine in cui compaiono."""
    groups: dict[SkipReason | None, list[Check]] = {}
    for c in skipped:
        groups.setdefault(c.skip_reason, []).append(c)
    return list(groups.items())


class JsonReporter:
    """Report in JSON, utile per integrazioni o salvataggio."""

    def render(self, result: ScanResult) -> str:
        return json.dumps(self.to_dict(result), indent=2, ensure_ascii=False)

    def to_dict(self, result: ScanResult) -> dict:
        return {
            "domain": result.domain,
            "score": result.score,
            "risk_level": result.level.name,
            "risk_description": result.level.description,
            "caps": [{"max_score": c.max_score, "reason": c.reason} for c in result.caps],
            "lookalike": asdict(result.lookalike) if result.lookalike else None,
            "redirect_target": result.redirect_target,
            "bot_block": result.bot_block,
            "unreliable": bool(result.bot_block),
            "chains": {label: [{"status": st, "url": url} for st, url in chain]
                       for label, chain in result.chains.items()},
            "destination": self._destination(result.destination),
            "categories": self._categories(result),
            "findings": [self._finding(c) for c in result.findings],
            "passed": [{"name": c.name, "category": c.category, "detected": c.message,
                        "source_url": c.source_url}
                       for c in result.checks if c.status == "OK"],
            "skipped": [{"name": c.name, "category": c.category, "reason": c.message,
                         "reason_label": c.skip_reason.label if c.skip_reason else None,
                         "explanation": c.skip_reason.text if c.skip_reason else None,
                         "source_url": c.source_url}
                        for c in result.checks if c.skipped],
        }

    @staticmethod
    def _destination(dest: ScanResult | None) -> dict | None:
        if dest is None:
            return None
        return {
            "domain": dest.domain,
            "score": dest.score,
            "risk_level": dest.level.name,
            "verdict": dest.lookalike.verdict if dest.lookalike else None,
            "unreliable": bool(dest.bot_block),
            "tls_legacy": next((c.message for c in dest.checks if c.name == "TLS 1.0/1.1 disabilitati"), None),
            "top_findings": [{"name": c.name, "severity": c.effective_severity.label, "detected": c.message}
                             for c in dest.findings[:3]],
        }

    @staticmethod
    def _categories(result: ScanResult) -> list[dict]:
        out = []
        for category, group in groupby(result.checks, key=lambda c: c.category):
            group = list(group)
            active = [c for c in group if not c.skipped]
            got = sum(c.points for c in active)
            tot = sum(c.max_points for c in active)
            out.append({
                "name": category,
                "verified": bool(active),
                "skip_reasons": list(dict.fromkeys(c.skip_reason.label for c in group
                                                   if c.skipped and c.skip_reason)),
                "points": round(got, 1),
                "max_points": tot,
                "percent": round(got / tot * 100) if tot else None,
            })
        return out

    @staticmethod
    def _finding(c: Check) -> dict:
        return {
            "name": c.name,
            "category": c.category,
            "severity": c.effective_severity.label,
            "points": c.points,
            "max_points": c.max_points,
            "lost_points": c.lost_points,
            "detected": c.message,
            "source_url": c.source_url,
            "why": c.why,
        }
