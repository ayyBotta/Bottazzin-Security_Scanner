"""Calcolo del punteggio di sicurezza e del livello di rischio."""

from __future__ import annotations

from .models import Check, RiskLevel, ScoreCap


class SecurityScorer:
    """
    Punteggio di sicurezza 0-100 (100 = sito sicuro, 0 = sito gravemente insicuro).

    Ogni controllo ha un peso (max_points):
        punteggio = somma(points) / somma(max_points dei controlli eseguiti) * 100
        punti persi da un controllo = (max_points - points) / somma(max_points eseguiti) * 100
    Poi si applicano i tetti dovuti a problemi critici (es. niente HTTPS => massimo 20).
    """

    LEVELS = [
        (85, RiskLevel("BASSO", "Il dominio adotta buone pratiche di sicurezza; i rischi residui sono marginali.")),
        (65, RiskLevel("MODERATO", "Configurazione discreta, ma con alcune lacune che andrebbero corrette.")),
        (45, RiskLevel("ELEVATO", "Mancano diverse protezioni importanti: il dominio e' esposto ad attacchi comuni.")),
        (25, RiskLevel("ALTO", "Gravi carenze di sicurezza: gli utenti del sito sono concretamente a rischio.")),
        (0, RiskLevel("CRITICO", "Il dominio e' gravemente insicuro: dati e utenti sono esposti ad attacchi banali.")),
    ]

    def compute(self, checks: list[Check], caps: list[ScoreCap]) -> int:
        active = [c for c in checks if not c.skipped]
        max_total = sum(c.max_points for c in active) or 1
        for c in active:
            c.lost_points = round((c.max_points - c.points) / max_total * 100, 1)

        score = round(sum(c.points for c in active) / max_total * 100)
        for cap in caps:
            score = min(score, cap.max_score)
        return max(score, 0)

    def qualify(self, score: int) -> RiskLevel:
        return next(level for threshold, level in self.LEVELS if score >= threshold)
