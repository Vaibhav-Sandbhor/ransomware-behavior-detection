"""
Translator Agent -- detects language and translates text to English.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents.base import BaseAgent

logger = logging.getLogger("mad_cti")

DETECT_PROMPT = """\
You are a language detection specialist. Analyze the provided text and determine its language.

Respond ONLY with a JSON object (no extra text):
{
  "original_language": "<ISO 639-1 code, e.g. 'en', 'ru', 'zh'>",
  "language_name": "<full language name, e.g. 'English', 'Russian'>",
  "is_english": <true | false>
}
"""

TRANSLATE_PROMPT = """\
You are a translation specialist working in a cyber threat intelligence pipeline.
Translate the following text to English while preserving technical jargon, slang, \
and forum-style formatting.

Respond ONLY with the translated English text, nothing else. No JSON, no explanation.
"""


class TranslatorAgent(BaseAgent):
    """Detects the source language and translates to English if needed."""

    agent_name = "TranslatorAgent"

    def process(self, input_data: Any) -> dict:
        """
        Parameters
        ----------
        input_data : str
            Raw text from the dataset.

        Returns
        -------
        dict with keys: original_language, language_name, was_translated, translated_text
        """
        if not isinstance(input_data, str) or not input_data.strip():
            return {
                "original_language": "unknown",
                "language_name": "Unknown",
                "was_translated": False,
                "translated_text": input_data or "",
            }

        # Step 1: Detect language (small JSON response — reliable)
        try:
            detect_response = self._call_claude(DETECT_PROMPT, input_data[:500])
            lang_info = self._extract_json(detect_response)
        except Exception as e:
            logger.warning("[TranslatorAgent] Language detection failed: %s. Assuming English.", e)
            lang_info = {"original_language": "en", "language_name": "English", "is_english": True}

        is_english = lang_info.get("is_english", True)

        # Step 2: If English, pass through directly (no LLM call needed)
        if is_english:
            return {
                "original_language": lang_info.get("original_language", "en"),
                "language_name": lang_info.get("language_name", "English"),
                "was_translated": False,
                "translated_text": input_data,  # Original text, no JSON wrapping issues
            }

        # Step 3: If not English, translate (response is plain text, not JSON)
        try:
            translated = self._call_claude(TRANSLATE_PROMPT, input_data)
        except Exception as e:
            logger.warning("[TranslatorAgent] Translation failed: %s. Using original.", e)
            translated = input_data

        return {
            "original_language": lang_info.get("original_language", "unknown"),
            "language_name": lang_info.get("language_name", "Unknown"),
            "was_translated": True,
            "translated_text": translated.strip(),
        }
