"""
Analyzer Agent — performs deep text analysis and extracts structured threat indicators.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent


SYSTEM_PROMPT = """\
You are a senior cyber threat intelligence analyst. You receive English text \
collected from dark web forums, marketplaces, and paste sites.

Analyze the text and produce a structured JSON report with these fields:

{
  "content_type": "<one of: forum_post, marketplace_listing, vulnerability_disclosure, advertisement, broken_page, paste, article, other>",
  "summary": "<concise 2-3 sentence summary of what the text is about>",
  "has_conversation": <true if the text contains a conversation/thread structure, else false>,
  "mentioned_tools": ["<tool1>", "<tool2>"],
  "mentioned_malware": ["<malware1>", "<malware2>"],
  "mentioned_attack_methods": ["<method1>", "<method2>"],
  "mentioned_vulnerabilities": ["<vuln1>", "<vuln2>"],
  "threat_indicators": {
    "selling_services": <true|false>,
    "selling_tools": <true|false>,
    "sharing_exploits": <true|false>,
    "sharing_guides": <true|false>,
    "contains_iocs": <true|false>
  }
}

Rules:
- Lists may be empty if nothing relevant is found.
- Use exact tool/malware names when identifiable.
- For vulnerabilities, include CVE IDs if present.
- Be precise; do NOT hallucinate items not mentioned in the text.
- Respond ONLY with the JSON object, no extra commentary.
"""


class AnalyzerAgent(BaseAgent):
    """Extracts structured threat intelligence indicators from English text."""

    agent_name = "AnalyzerAgent"

    # Default structure when analysis fails
    _EMPTY_ANALYSIS: dict = {
        "content_type": "other",
        "summary": "Unable to analyze content.",
        "has_conversation": False,
        "mentioned_tools": [],
        "mentioned_malware": [],
        "mentioned_attack_methods": [],
        "mentioned_vulnerabilities": [],
        "threat_indicators": {
            "selling_services": False,
            "selling_tools": False,
            "sharing_exploits": False,
            "sharing_guides": False,
            "contains_iocs": False,
        },
    }

    def process(self, input_data: Any) -> dict:
        """
        Parameters
        ----------
        input_data : str
            English text (output of TranslatorAgent).

        Returns
        -------
        dict — structured analysis JSON.
        """
        if not isinstance(input_data, str) or not input_data.strip():
            return dict(self._EMPTY_ANALYSIS)

        raw_response = self._call_claude(SYSTEM_PROMPT, input_data)
        result = self._extract_json(raw_response)

        # Merge with defaults so downstream agents always get expected keys
        merged = dict(self._EMPTY_ANALYSIS)
        merged.update(result)
        return merged
