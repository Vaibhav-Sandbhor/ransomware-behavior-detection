"""
CTI Pipeline Orchestrator — chains all agents in sequence.

Flow: Translator → Analyzer → Relevancy → Category → (optional) Risk Scorer
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from agents.translator import TranslatorAgent
from agents.analyzer import AnalyzerAgent
from agents.relevancy import RelevancyAgent
from agents.category import CategoryAgent

logger = logging.getLogger("mad_cti")


class CTIPipeline:
    """
    Orchestrates the multi-agent CTI analysis pipeline.
    Each document flows through: Translate → Analyze → Relevancy → Category.
    """

    def __init__(self, *, enable_risk_scoring: bool = False) -> None:
        logger.info("Initializing CTI Pipeline agents...")

        self.translator = TranslatorAgent()
        self.analyzer = AnalyzerAgent()
        self.relevancy = RelevancyAgent()
        self.category = CategoryAgent()

        self._risk_scorer = None
        if enable_risk_scoring:
            from agents.risk_scorer import RiskScorerAgent
            self._risk_scorer = RiskScorerAgent()

        logger.info("All agents initialized successfully.")

    def run(self, document: dict) -> dict:
        """
        Process a single document through the full pipeline.

        Parameters
        ----------
        document : dict
            Must have "id" and "text" keys.

        Returns
        -------
        dict — final structured result.
        """
        doc_id = document.get("id", "unknown")
        raw_text = document.get("text", "")

        logger.info("=" * 60)
        logger.info("Processing document: %s", doc_id)
        pipeline_start = time.time()

        # ── Step 1: Translation ────────────────────────────────────────
        logger.info("[Step 1/4] Running TranslatorAgent...")
        translation_result = self.translator.process(raw_text)
        english_text = translation_result["translated_text"]
        logger.info(
            "  Language: %s | Translated: %s",
            translation_result["language_name"],
            translation_result["was_translated"],
        )

        # ── Step 2: Analysis ───────────────────────────────────────────
        logger.info("[Step 2/4] Running AnalyzerAgent...")
        analysis_result = self.analyzer.process(english_text)
        logger.info(
            "  Content type: %s | Tools: %d | Malware: %d | Vulns: %d",
            analysis_result.get("content_type", "?"),
            len(analysis_result.get("mentioned_tools", [])),
            len(analysis_result.get("mentioned_malware", [])),
            len(analysis_result.get("mentioned_vulnerabilities", [])),
        )

        # ── Step 3: Relevancy ─────────────────────────────────────────
        logger.info("[Step 3/4] Running RelevancyAgent...")
        relevancy_result = self.relevancy.process(analysis_result)
        logger.info(
            "  Relevancy: %s", relevancy_result["relevancy"]
        )

        # ── Step 4: Category ──────────────────────────────────────────
        logger.info("[Step 4/4] Running CategoryAgent...")
        category_input = {
            "analysis": analysis_result,
            "relevancy": relevancy_result["relevancy"],
        }
        category_result = self.category.process(category_input)
        logger.info(
            "  Category: %s (confidence: %.2f)",
            category_result["category"],
            category_result["confidence_score"],
        )

        # ── (Optional) Step 5: Risk Scoring ───────────────────────────
        risk_result = {}
        if self._risk_scorer and relevancy_result["relevancy"] == "Relevant":
            logger.info("[Step 5] Running RiskScorerAgent...")
            risk_input = {
                "analysis": analysis_result,
                "category": category_result["category"],
                "confidence_score": category_result["confidence_score"],
            }
            risk_result = self._risk_scorer.process(risk_input)
            logger.info(
                "  Risk: %.2f (%s)",
                risk_result.get("risk_score", 0),
                risk_result.get("risk_level", "N/A"),
            )

        elapsed = time.time() - pipeline_start
        logger.info("Document %s processed in %.2fs", doc_id, elapsed)

        # ── Assemble final output ─────────────────────────────────────
        output = {
            "id": doc_id,
            "relevancy": relevancy_result["relevancy"],
            "relevancy_justification": relevancy_result["justification"],
            "category": category_result["category"],
            "confidence_score": category_result["confidence_score"],
            "category_reasoning": category_result["reasoning"],
            "analysis_summary": analysis_result.get("summary", ""),
            "content_type": analysis_result.get("content_type", ""),
            "mentioned_tools": analysis_result.get("mentioned_tools", []),
            "mentioned_malware": analysis_result.get("mentioned_malware", []),
            "mentioned_attack_methods": analysis_result.get("mentioned_attack_methods", []),
            "mentioned_vulnerabilities": analysis_result.get("mentioned_vulnerabilities", []),
            "original_language": translation_result["original_language"],
            "was_translated": translation_result["was_translated"],
            "processing_time_seconds": round(elapsed, 2),
        }

        # Merge risk scoring if available
        if risk_result:
            output["risk_score"] = risk_result.get("risk_score", 0.0)
            output["risk_level"] = risk_result.get("risk_level", "N/A")
            output["risk_factors"] = risk_result.get("risk_factors", [])

        return output

    def run_batch(self, documents: list[dict]) -> list[dict]:
        """Process a list of documents and return all results."""
        results = []
        total = len(documents)

        for i, doc in enumerate(documents, 1):
            logger.info("Processing document %d / %d", i, total)
            try:
                result = self.run(doc)
                results.append(result)
            except Exception as exc:
                logger.error(
                    "Failed to process document %s: %s",
                    doc.get("id", "?"),
                    exc,
                )
                results.append({
                    "id": doc.get("id", "unknown"),
                    "relevancy": "Error",
                    "category": "Error",
                    "confidence_score": 0.0,
                    "analysis_summary": f"Processing failed: {exc}",
                    "error": str(exc),
                })

        return results
