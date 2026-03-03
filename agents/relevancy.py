"""
Relevancy Classifier Agent — determines if analyzed content is relevant to CTI.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base import BaseAgent


SYSTEM_PROMPT = """\
You are a cyber threat intelligence relevancy classifier.

You will receive a structured JSON analysis of a text document. Based ONLY on \
this analysis (you will NOT see the original text), determine whether the \
content is relevant to cyber threat intelligence.

Relevant content includes:
- Hacking guides, tutorials, or technique discussions
- Malware sales, development, or distribution
- Vulnerability disclosures, exploits, or PoCs
- Selling hacking services or tools
- Sharing of indicators of compromise (IOCs)

NOT relevant content includes:
- Generic advertisements unrelated to hacking/security
- Broken/garbled/error pages
- Legitimate product sales
- Non-security forum discussions

Respond ONLY with a JSON object:
{
  "relevancy": "Relevant" or "Not Relevant",
  "justification": "<2-3 sentence explanation of your decision>"
}
"""


class RelevancyAgent(BaseAgent):
    """Classifies whether an analysis is relevant to cyber threat intelligence."""

    agent_name = "RelevancyAgent"

    def process(self, input_data: Any) -> dict:
        """
        Parameters
        ----------
        input_data : dict
            The structured analysis JSON from AnalyzerAgent.

        Returns
        -------
        dict with keys: relevancy, justification
        """
        # Convert the analysis dict to a JSON string for Claude
        analysis_text = json.dumps(input_data, indent=2)

        raw_response = self._call_claude(SYSTEM_PROMPT, analysis_text)
        result = self._extract_json(raw_response)

        return {
            "relevancy": result.get("relevancy", "Not Relevant"),
            "justification": result.get("justification", "No justification provided."),
        }
