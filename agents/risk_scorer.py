"""
Risk Scorer Agent — assigns a risk score and level to relevant CTI documents.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent


SYSTEM_PROMPT = """\
You are a cyber threat risk assessment specialist.

You receive a structured analysis of a dark web document that has been classified \
as relevant to cyber threat intelligence, along with its category.

Your task is to assign a risk score from 0.0 to 1.0 and a risk level.

Risk Level Scale:
- Low (0.0 - 0.3): Informational, low-impact discussions, general awareness
- Medium (0.3 - 0.6): Active sharing of techniques or tools with moderate impact
- High (0.6 - 0.8): Active selling of tools/services, detailed exploit code, \
  ready-to-use attack guides
- Critical (0.8 - 1.0): Zero-day exploits, active campaigns, critical \
  infrastructure targeting, mass-impact threats

Consider these risk factors:
1. **Immediacy**: Is the threat active/current or theoretical?
2. **Accessibility**: How easy is it for a low-skill attacker to use this?
3. **Impact Scope**: Individual targets vs. mass/enterprise impact?
4. **Commercialization**: Is this being sold as a service/product?
5. **Sophistication**: How advanced is the technique/tool?

Respond ONLY with a JSON object:
{
  "risk_score": <float 0.0 to 1.0>,
  "risk_level": "Low" | "Medium" | "High" | "Critical",
  "risk_factors": [
    "<factor 1: brief description>",
    "<factor 2: brief description>"
  ],
  "reasoning": "<1-2 sentence explanation>"
}
"""


class RiskScorerAgent(BaseAgent):
    """Assigns a risk score and risk level to relevant CTI documents."""

    agent_name = "RiskScorerAgent"

    def process(self, input_data: Any) -> dict:
        """
        Parameters
        ----------
        input_data : dict
            Must contain:
              - "analysis": dict from AnalyzerAgent
              - "category": str from CategoryAgent
              - "confidence_score": float from CategoryAgent

        Returns
        -------
        dict with keys: risk_score, risk_level, risk_factors, reasoning
        """
        context = json.dumps(input_data, indent=2)
        raw_response = self._call_claude(SYSTEM_PROMPT, context)
        result = self._extract_json(raw_response)

        # Validate risk_level
        valid_levels = {"Low", "Medium", "High", "Critical"}
        risk_level = result.get("risk_level", "Medium")
        if risk_level not in valid_levels:
            risk_level = "Medium"

        # Clamp risk_score
        risk_score = float(result.get("risk_score", 0.5))
        risk_score = max(0.0, min(1.0, risk_score))

        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "risk_factors": result.get("risk_factors", []),
            "reasoning": result.get("reasoning", "No reasoning provided."),
        }
