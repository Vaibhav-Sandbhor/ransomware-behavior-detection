"""
Category Classification Agent — classifies relevant content into Hack / Malware / Vulnerability.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent


SYSTEM_PROMPT = """\
You are a cyber threat intelligence category classifier.

You will receive a structured analysis JSON of a document that has already been \
determined to be RELEVANT to cyber threat intelligence.

Classify the document into exactly ONE of these categories:

1. **Hack** — The content primarily discusses hacking guides, services, or \
   techniques such as phishing, SQL injection, brute-forcing, account cracking, \
   social engineering, or penetration testing tutorials.

2. **Malware** — The content primarily discusses malicious software such as \
   ransomware, trojans, spyware, keyloggers, RATs, stealers, botnets, or \
   malware-as-a-service offerings.

3. **Vulnerability** — The content primarily discusses specific exploits, bugs, \
   CVEs, system weaknesses, zero-days, or proof-of-concept exploit code.

If the content overlaps multiple categories, choose the DOMINANT one.

Respond ONLY with a JSON object:
{
  "category": "Hack" | "Malware" | "Vulnerability",
  "confidence_score": <float 0.0 to 1.0>,
  "reasoning": "<1-2 sentence explanation>"
}
"""


class CategoryAgent(BaseAgent):
    """
    Classifies relevant CTI content into Hack / Malware / Vulnerability.
    Automatically assigns 'N/A' if the document was marked Not Relevant.
    """

    agent_name = "CategoryAgent"

    def process(self, input_data: Any) -> dict:
        """
        Parameters
        ----------
        input_data : dict
            Must contain:
              - "analysis": dict from AnalyzerAgent
              - "relevancy": str ("Relevant" or "Not Relevant")

        Returns
        -------
        dict with keys: category, confidence_score, reasoning
        """
        relevancy = input_data.get("relevancy", "Not Relevant")

        # Short-circuit: if not relevant, auto-assign N/A
        if relevancy != "Relevant":
            return {
                "category": "N/A",
                "confidence_score": 1.0,
                "reasoning": "Document was classified as not relevant to CTI; "
                             "category automatically set to N/A.",
            }

        analysis = input_data.get("analysis", {})
        analysis_text = json.dumps(analysis, indent=2)

        raw_response = self._call_claude(SYSTEM_PROMPT, analysis_text)
        result = self._extract_json(raw_response)

        # Validate category
        valid_categories = {"Hack", "Malware", "Vulnerability"}
        category = result.get("category", "Hack")
        if category not in valid_categories:
            category = "Hack"  # fallback

        return {
            "category": category,
            "confidence_score": float(result.get("confidence_score", 0.5)),
            "reasoning": result.get("reasoning", "No reasoning provided."),
        }
