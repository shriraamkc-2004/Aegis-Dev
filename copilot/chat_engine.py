"""
Aegis Copilot — Chat Engine
Orchestrates RAG retrieval → context injection → Gemini generation → Responsible AI guardrails.
Supports: Analyst Assistant, Audit Assistant, Documentation Assistant, Incident Intelligence.
"""

from __future__ import annotations

import logging
import time
from typing import Optional, List, Dict, Any

from copilot.config import (
    GEMINI_API_KEY,
    GEMINI_MODEL,
    RAI_MAX_RESPONSE_TOKENS,
    RAI_TEMPERATURE,
    QDRANT_COLLECTION_KNOWLEDGE,
    QDRANT_COLLECTION_ALERTS,
    QDRANT_COLLECTION_INCIDENTS,
    QDRANT_COLLECTION_LOGS,
)
from copilot.rag_pipeline import RAGPipeline, GeminiEmbedder
from copilot.responsible_ai import (
    ResponsibleAIEngine,
    AuditLogger,
    AuditEntry,
    CopilotResponse,
    SourceAttribution,
)
from copilot.vector_store import VectorStore

logger = logging.getLogger(__name__)

# ─── Assistant Personas ──────────────────────────────────────────────────────────

ASSISTANT_PERSONAS = {
    "analyst": {
        "name": "Analyst Assistant",
        "description": "Explain anomalies, severity decisions, recommend mitigations, guide investigations.",
        "collections": [QDRANT_COLLECTION_ALERTS, QDRANT_COLLECTION_INCIDENTS, QDRANT_COLLECTION_KNOWLEDGE],
        "system_hint": (
            "You are the Aegis Analyst Assistant. Help SOC analysts understand anomalies, "
            "explain severity decisions, recommend mitigations, and guide investigations. "
            "Always reference specific data points and retrieved evidence."
        ),
    },
    "audit": {
        "name": "Audit Assistant",
        "description": "Summarize audit findings, highlight critical risks, recommend OWASP improvements.",
        "collections": [QDRANT_COLLECTION_INCIDENTS, QDRANT_COLLECTION_LOGS, QDRANT_COLLECTION_KNOWLEDGE],
        "system_hint": (
            "You are the Aegis Audit Assistant. Summarize audit findings, highlight critical risks, "
            "and recommend OWASP Top 10 improvements. Cite specific evidence from audit logs."
        ),
    },
    "documentation": {
        "name": "Documentation Assistant",
        "description": "Explain architecture, workflows, provide setup assistance.",
        "collections": [QDRANT_COLLECTION_KNOWLEDGE],
        "system_hint": (
            "You are the Aegis Documentation Assistant. Explain system architecture, workflows, "
            "setup procedures, and operational guides. Reference documentation sources explicitly."
        ),
    },
    "incident": {
        "name": "Incident Intelligence",
        "description": "Retrieve similar incidents, summarize investigations, recommend next steps.",
        "collections": [QDRANT_COLLECTION_INCIDENTS, QDRANT_COLLECTION_ALERTS, QDRANT_COLLECTION_LOGS],
        "system_hint": (
            "You are the Aegis Incident Intelligence Assistant. Retrieve similar historical incidents, "
            "summarize previous investigations, and recommend next steps based on lessons learned."
        ),
    },
}


class ChatEngine:
    """
    Main chat orchestration engine.
    Combines RAG retrieval, Gemini generation, and Responsible AI guardrails.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        rag_pipeline: RAGPipeline,
        rai_engine: ResponsibleAIEngine,
        audit_logger: AuditLogger,
    ):
        self._vs = vector_store
        self._rag = rag_pipeline
        self._rai = rai_engine
        self._audit = audit_logger
        self._gemini_client = None
        self._init_gemini()

    def _init_gemini(self):
        if GEMINI_API_KEY and GEMINI_API_KEY not in ("MY_GEMINI_API_KEY", ""):
            try:
                from google import genai
                self._gemini_client = genai.Client(api_key=GEMINI_API_KEY)
                logger.info("Gemini client initialized for Copilot chat.")
            except Exception as exc:
                logger.warning("Gemini init failed: %s", exc)
                self._gemini_client = None

    # ─── Chat ────────────────────────────────────────────────────────────────────

    def chat(
        self,
        user_message: str,
        assistant: str = "analyst",
        user_id: Optional[int] = None,
        session_id: Optional[int] = None,
        ip_address: str = "",
        chat_history: Optional[List[Dict[str, str]]] = None,
        tenant_id: Optional[int] = None,
    ) -> CopilotResponse:
        """
        Process a user message through the full RAG → Gemini → RAI pipeline.
        Tenant-isolated: retrieval scoped to tenant_id when provided.
        """
        persona = ASSISTANT_PERSONAS.get(assistant, ASSISTANT_PERSONAS["analyst"])
        collections = persona["collections"]

        # Step 1: RAG Retrieval (tenant-isolated)
        context_text, sources_raw, max_confidence = self._rag.build_context(
            user_message, collections=collections, tenant_id=tenant_id
        )

        sources = [
            SourceAttribution(
                index=s["index"],
                source=s["source"],
                filename=s["filename"],
                collection=s["collection"],
                score=s["score"],
            )
            for s in sources_raw
        ]

        # Step 2: Build Gemini prompt with RAG context
        system_prompt = self._build_system_prompt(persona, context_text, chat_history)

        # Step 3: Gemini generation
        raw_answer = self._call_gemini(system_prompt, user_message)

        # Step 4: Responsible AI guardrails
        response = self._rai.assemble_response(
            raw_answer=raw_answer,
            sources=sources,
            confidence=max_confidence,
            user_prompt=user_message,
            user_id=user_id,
            session_id=session_id,
            model=GEMINI_MODEL,
        )

        # Step 5: Audit log
        self._audit.log(AuditEntry(
            user_id=user_id,
            prompt=user_message,
            retrieved_documents=[s.__dict__ for s in sources],
            gemini_response=response.answer[:500],
            confidence=max_confidence,
            sources_used=len(sources),
            evidence_sufficient=response.evidence_sufficient,
            requires_approval=response.requires_approval,
            ip_address=ip_address,
            session_id=session_id,
        ))

        return response

    # ─── Prompt Builder ──────────────────────────────────────────────────────────

    def _build_system_prompt(
        self,
        persona: Dict[str, Any],
        context_text: str,
        chat_history: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Build the system prompt with RAG context injection."""
        parts = [
            persona["system_hint"],
            "",
            "RESPONSIBLE AI RULES:",
            "1. Always cite which documents you retrieved and their relevance.",
            "2. Indicate your confidence level in the answer.",
            "3. If evidence is insufficient, state that clearly — do not fabricate.",
            "4. NEVER autonomously execute high-impact actions (blocking users, isolating endpoints, etc.).",
            "5. For critical actions, recommend analyst approval.",
            "6. Always indicate that responses are generated using Google Gemini 2.5 Flash.",
            "7. Always list the RAG sources used.",
        ]

        if context_text:
            parts.extend([
                "",
                "RETRIEVED ENTERPRISE KNOWLEDGE (use this as primary evidence):",
                "---",
                context_text,
                "---",
            ])
        else:
            parts.extend([
                "",
                "NOTE: No relevant documents were retrieved from the knowledge base.",
                "If the question requires enterprise-specific knowledge, indicate that",
                "insufficient evidence was found.",
            ])

        if chat_history:
            parts.append("")
            parts.append("RECENT CONVERSATION HISTORY:")
            for msg in chat_history[-6:]:
                role = "User" if msg.get("role") == "user" else "Assistant"
                parts.append(f"  {role}: {msg.get('message', '')[:200]}")

        return "\n".join(parts)

    # ─── Gemini Call ─────────────────────────────────────────────────────────────

    def _call_gemini(self, system_prompt: str, user_message: str) -> str:
        """Call Gemini for response generation."""
        if not self._gemini_client:
            return self._fallback_response(user_message)

        try:
            response = self._gemini_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=[
                    {"role": "user", "parts": [{"text": system_prompt + "\n\nUser Question: " + user_message}]},
                ],
                config={
                    "temperature": RAI_TEMPERATURE,
                    "max_output_tokens": RAI_MAX_RESPONSE_TOKENS,
                },
            )
            return response.text or self._fallback_response(user_message)
        except Exception as exc:
            logger.error("Gemini chat error: %s", exc)
            return self._fallback_response(user_message)

    def _fallback_response(self, user_message: str) -> str:
        """Deterministic fallback when Gemini is unavailable."""
        return (
            "The AI service is currently unavailable. Based on your query, I recommend "
            "consulting the Aegis documentation or contacting a senior SOC analyst. "
            "Your question has been logged for audit purposes."
        )

    # ─── Approval Workflow ────────────────────────────────────────────────────────

    def approve_action(
        self,
        response_id: str,
        approved: bool,
        approver_id: int,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Process analyst approval/denial for a high-impact action.
        """
        return {
            "response_id": response_id,
            "approved": approved,
            "approver_id": approver_id,
            "notes": notes,
            "timestamp": time.time(),
            "status": "approved" if approved else "denied",
        }

    # ─── Health ──────────────────────────────────────────────────────────────────

    def is_healthy(self) -> Dict[str, bool]:
        return {
            "gemini": self._gemini_client is not None,
            "qdrant": self._vs.is_healthy(),
            "rag": True,
        }
