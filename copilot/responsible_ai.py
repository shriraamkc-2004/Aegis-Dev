"""
Aegis Copilot — Responsible AI Layer
Implements: Human-in-the-Loop, Explainability, Transparency,
Hallucination Reduction, and Auditability.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from copilot.config import (
    RAG_CONFIDENCE_THRESHOLD,
    RAG_CONFIDENCE_HIGH,
    RAG_CONFIDENCE_MODERATE,
    HIGH_IMPACT_ACTIONS,
)

logger = logging.getLogger(__name__)


# ─── Data Structures ─────────────────────────────────────────────────────────────


@dataclass
class SourceAttribution:
    index: int
    source: str
    filename: str
    collection: str
    score: float


@dataclass
class CopilotResponse:
    """
    Every AI response includes full Responsible AI metadata.
    """
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    answer: str = ""
    # Explainability
    reasoning: str = ""
    confidence: float = 0.0
    confidence_level: str = "low"  # "high", "moderate", "low"
    sources: List[SourceAttribution] = field(default_factory=list)
    # Transparency
    model_used: str = "gemini-2.5-flash"
    rag_sources_used: bool = False
    evidence_sufficient: bool = True
    # HITL
    requires_approval: bool = False
    pending_action: Optional[str] = None
    # Metadata
    timestamp: float = field(default_factory=time.time)
    user_id: Optional[int] = None
    session_id: Optional[int] = None
    prompt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sources"] = [asdict(s) for s in self.sources]
        return d


@dataclass
class AuditEntry:
    """Immutable audit log record for every AI interaction."""
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[int] = None
    user_email: str = ""
    prompt: str = ""
    retrieved_documents: List[Dict[str, Any]] = field(default_factory=list)
    gemini_response: str = ""
    confidence: float = 0.0
    sources_used: int = 0
    evidence_sufficient: bool = True
    requires_approval: bool = False
    approved_by: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    ip_address: str = ""
    session_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Responsible AI Engine ───────────────────────────────────────────────────────


class ResponsibleAIEngine:
    """
    Wraps every Gemini response with enterprise safety guardrails.
    Implements 3-tier confidence framework:
      - High: >= 80% (display normally)
      - Moderate: 50-79% (display with caution notice)
      - Low: < 50% (safe fallback response)
    """

    def __init__(
        self,
        confidence_threshold: float = RAG_CONFIDENCE_THRESHOLD,
        confidence_high: float = RAG_CONFIDENCE_HIGH,
        confidence_moderate: float = RAG_CONFIDENCE_MODERATE,
    ):
        self._threshold = confidence_threshold
        self._high = confidence_high
        self._moderate = confidence_moderate

    def classify_confidence(self, confidence: float) -> str:
        """Classify confidence into 3 tiers: high, moderate, low."""
        if confidence >= self._high:
            return "high"
        elif confidence >= self._moderate:
            return "moderate"
        return "low"

    # ─── Hallucination Reduction ─────────────────────────────────────────────────

    def check_evidence(self, confidence: float, sources: List[SourceAttribution]) -> bool:
        """
        Return True if retrieved evidence is sufficient to answer.
        If False, the copilot must refuse to fabricate an answer.
        """
        if not sources:
            return False
        if confidence < self._threshold:
            return False
        return True

    def hallucination_guard_response(self) -> str:
        """
        Standard response when evidence is insufficient.
        The AI must NEVER fabricate answers.
        """
        return (
            "I could not find sufficient evidence in the indexed knowledge base "
            "to answer this confidently. Please provide more context, upload "
            "relevant documentation, or consult a senior analyst."
        )

    # ─── Human-in-the-Loop ───────────────────────────────────────────────────────

    def detect_high_impact_action(self, user_prompt: str, ai_response: str) -> Optional[str]:
        """
        Inspect the AI response for high-impact actions that require analyst approval.
        Returns the action name if detected, None otherwise.
        """
        combined = (user_prompt + " " + ai_response).lower()
        for action in HIGH_IMPACT_ACTIONS:
            if action.replace("_", " ") in combined or action in combined:
                return action
        return None

    def build_approval_prompt(self, action: str, context: str) -> str:
        """Build a human-readable approval request for the analyst."""
        return (
            f"⚠ HIGH-IMPACT ACTION REQUIRES APPROVAL\n\n"
            f"Action: {action}\n"
            f"Context: {context}\n\n"
            f"This action may isolate endpoints, block users, or modify security controls.\n"
            f"Please review and approve or deny this action.\n"
        )

    # ─── Explainability ──────────────────────────────────────────────────────────

    def build_explanation(
        self,
        sources: List[SourceAttribution],
        confidence: float,
        model: str,
    ) -> str:
        """
        Build a transparency block appended to every AI response.
        """
        lines = [
            "",
            "---",
            "**Explainability & Transparency**",
            f"- Model: `{model}` (Google Gemini 2.5 Flash)",
            f"- Confidence: `{confidence:.2f}`",
            f"- Sources retrieved: `{len(sources)}`",
        ]
        if sources:
            lines.append("- Evidence:")
            for s in sources[:5]:
                lines.append(f"  - [{s.index}] `{s.filename}` (relevance: {s.score:.2f}, collection: `{s.collection}`)")
        else:
            lines.append("- No supporting evidence retrieved from knowledge base.")
        lines.append("---")
        return "\n".join(lines)

    # ─── Response Assembly ────────────────────────────────────────────────────────

    def assemble_response(
        self,
        raw_answer: str,
        sources: List[SourceAttribution],
        confidence: float,
        user_prompt: str,
        user_id: Optional[int] = None,
        session_id: Optional[int] = None,
        model: str = "gemini-2.5-flash",
    ) -> CopilotResponse:
        """
        Apply all Responsible AI guardrails and assemble a final response.
        3-tier confidence:
          - High (>=80%): Display normally
          - Moderate (50-79%): Display with caution notice
          - Low (<50%): Safe fallback response
        """
        confidence_level = self.classify_confidence(confidence)
        evidence_ok = self.check_evidence(confidence, sources)
        high_impact = self.detect_high_impact_action(user_prompt, raw_answer)

        if not evidence_ok or confidence_level == "low":
            final_answer = self.hallucination_guard_response()
        elif confidence_level == "moderate":
            caution = (
                "\n\n> **Caution**: This response has moderate confidence "
                f"({confidence*100:.0f}%). Please verify with additional sources.\n"
            )
            final_answer = raw_answer + caution
        else:
            final_answer = raw_answer

        explanation = self.build_explanation(sources, confidence, model)
        final_answer_with_explanation = final_answer + "\n" + explanation

        resp = CopilotResponse(
            answer=final_answer_with_explanation,
            reasoning=f"Confidence={confidence:.2f} ({confidence_level}), sources={len(sources)}, evidence_sufficient={evidence_ok}",
            confidence=confidence,
            confidence_level=confidence_level,
            sources=sources,
            model_used=model,
            rag_sources_used=len(sources) > 0,
            evidence_sufficient=evidence_ok,
            requires_approval=high_impact is not None,
            pending_action=high_impact,
            user_id=user_id,
            session_id=session_id,
            prompt=user_prompt,
        )

        return resp


# ─── Audit Logger ────────────────────────────────────────────────────────────────


class AuditLogger:
    """
    Persists all AI interaction audit records to PostgreSQL.
    Falls back to in-memory list if PostgreSQL is unavailable.
    """

    def __init__(self, pg_connection=None):
        self._pg = pg_connection
        self._memory_log: List[AuditEntry] = []

    def log(self, entry: AuditEntry) -> None:
        self._memory_log.append(entry)
        if self._pg:
            try:
                self._persist_to_pg(entry)
            except Exception as exc:
                logger.warning("PG audit log failed: %s", exc)

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._memory_log[-limit:]]

    def _persist_to_pg(self, entry: AuditEntry) -> None:
        if not self._pg:
            return
        import psycopg2
        conn = psycopg2.connect(self._pg)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_logs
                        (user_id, action, resource, timestamp, ip_address, details)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        entry.user_id,
                        "COPILOT_QUERY",
                        "copilot",
                        entry.timestamp,
                        entry.ip_address,
                        f"prompt={entry.prompt[:200]}|confidence={entry.confidence:.2f}|"
                        f"sources={entry.sources_used}|evidence_ok={entry.evidence_sufficient}|"
                        f"approval_required={entry.requires_approval}",
                    ),
                )
                conn.commit()
        finally:
            conn.close()
