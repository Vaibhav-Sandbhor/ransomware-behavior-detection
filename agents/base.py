"""
Base agent class for all MAD-CTI agents.
Provides shared Ollama client, structured calling, logging, and retry logic.
"""

from __future__ import annotations

import json
import time
import logging
from abc import ABC, abstractmethod
from typing import Any

import requests

import config

logger = logging.getLogger("mad_cti")


class BaseAgent(ABC):
    """
    Abstract base for every agent in the pipeline.

    Subclasses must:
      1. Set `agent_name` (used in logs).
      2. Implement `process(input_data) -> dict`.
    """

    agent_name: str = "BaseAgent"

    def __init__(self) -> None:
        self._base_url = config.OLLAMA_BASE_URL
        self._model = config.MODEL_NAME
        self._max_tokens = config.MAX_TOKENS

    # -- Core contract --
    @abstractmethod
    def process(self, input_data: Any) -> dict:
        """Run the agent on the given input and return a structured dict."""
        ...

    # -- Ollama helper --
    def _call_claude(
        self,
        system_prompt: str,
        user_message: str,
        *,
        max_retries: int = 3,
        temperature: float = 0.2,
    ) -> str:
        """
        Send a message to Ollama (local LLM) and return the text response.
        Method name kept as _call_claude for backward compatibility with agent subclasses.
        Includes retry logic.
        """
        last_error: Exception | None = None

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": self._max_tokens,
            },
        }

        for attempt in range(1, max_retries + 1):
            try:
                start = time.time()

                response = requests.post(
                    f"{self._base_url}/api/chat",
                    json=payload,
                    timeout=300,  # Local LLMs can be slow on CPU
                )
                response.raise_for_status()

                result = response.json()
                text = result["message"]["content"]
                elapsed = time.time() - start

                logger.info(
                    "[%s] call succeeded in %.2fs (attempt %d)",
                    self.agent_name,
                    elapsed,
                    attempt,
                )
                logger.debug(
                    "[%s] prompt_snippet=%.120s...",
                    self.agent_name,
                    user_message[:120],
                )
                logger.debug("[%s] response=%.300s...", self.agent_name, text[:300])

                return text

            except requests.ConnectionError as exc:
                last_error = exc
                logger.error(
                    "[%s] Cannot connect to Ollama at %s. Is it running?",
                    self.agent_name,
                    self._base_url,
                )
                if attempt == max_retries:
                    break
                time.sleep(2)

            except Exception as exc:
                last_error = exc
                wait = 2 ** attempt
                logger.warning(
                    "[%s] Error (attempt %d/%d): %s -- retrying in %ds",
                    self.agent_name,
                    attempt,
                    max_retries,
                    str(exc)[:200],
                    wait,
                )
                if attempt == max_retries:
                    break
                time.sleep(wait)

        raise RuntimeError(
            f"[{self.agent_name}] Failed after {max_retries} retries: {last_error}"
        )

    # -- JSON extraction helper --
    @staticmethod
    def _extract_json(text: str) -> dict:
        """
        Extract a JSON object from the model's response.
        Robust against common local-LLM quirks:
          - Markdown code fences
          - Extra text before/after JSON
          - Unescaped newlines inside string values
          - Control characters
        """
        import re

        cleaned = text.strip()

        # Strip markdown code fences
        if "```" in cleaned:
            # Extract content between first ``` and last ```
            parts = cleaned.split("```")
            if len(parts) >= 3:
                # Take the content between first and last fences
                inner = parts[1]
                # Remove language identifier (e.g., "json\n")
                if inner.startswith(("json", "JSON")):
                    inner = inner[4:]
                cleaned = inner.strip()

        # Try direct parse first
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Find the outermost { ... } block
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_str = cleaned[start : end + 1]

            # Try parsing as-is
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # Fix common issues: replace literal newlines within strings
            # by processing line by line
            try:
                # Remove control characters except \n and \t
                json_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', json_str)

                # Try to fix unescaped newlines in string values
                # Replace newlines that appear inside quoted strings
                fixed = []
                in_string = False
                escape_next = False
                for ch in json_str:
                    if escape_next:
                        fixed.append(ch)
                        escape_next = False
                        continue
                    if ch == '\\':
                        fixed.append(ch)
                        escape_next = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        fixed.append(ch)
                        continue
                    if in_string and ch == '\n':
                        fixed.append('\\n')
                        continue
                    if in_string and ch == '\t':
                        fixed.append('\\t')
                        continue
                    fixed.append(ch)

                json_str = ''.join(fixed)
                return json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                pass

        raise ValueError(f"Could not parse JSON from response: {cleaned[:300]}")
