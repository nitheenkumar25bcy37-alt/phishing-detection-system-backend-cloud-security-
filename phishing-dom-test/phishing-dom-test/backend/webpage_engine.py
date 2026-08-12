"""
webpage_engine.py — Member 2: Webpage & DOM Analysis (backend half)

Takes the page_features JSON sent by content.js and turns it into a risk
score + list of triggered indicators. Pure rule-based logic for the MVP —
no ML here, that's Member 3's job.
"""

from typing import TypedDict, List


class PageFeatures(TypedDict):
    form_count: int
    password_fields: int
    hidden_iframes: int
    has_external_action: bool


def score_webpage(features: PageFeatures) -> dict:
    score = 0.0
    indicators: List[str] = []

    if features.get("password_fields", 0) > 0:
        score += 0.4
        indicators.append("password_form_present")

    if features.get("has_external_action"):
        score += 0.3
        indicators.append("form_action_external")

    if features.get("hidden_iframes", 0) > 0:
        score += 0.3
        indicators.append("hidden_iframe_detected")

    score = min(score, 1.0)
    risk = "SUSPICIOUS" if score >= 0.5 else "LOW"

    return {
        "webpage_score": round(score, 2),
        "risk": risk,
        "indicators": indicators,
    }
