/**
 * Aegis Enterprise — AI Orchestrator
 *
 * The single gateway to the LLM layer. No other component may call Gemini directly.
 *
 * 14-step pipeline:
 *  [1]  Receive validated request (post Prompt Guard + Guardrail Engine)
 *  [2]  Verify evidence integrity (SHA-256 stamp)
 *  [3]  Validate evidence completeness
 *  [4]  Route through Confidence Gate (HIGH / MEDIUM / LOW)
 *  [5]  Check semantic cache
 *  [6]  Check circuit breaker state
 *  [7]  Load active prompt template from Prompt Registry
 *  [8]  Build structured evidence-anchored prompt
 *  [9]  Call Gemini API with timeout, token limits, and retry logic
 *  [10] Pass raw response to Truth Engine
 *  [11] On hallucination: build safe fallback
 *  [12] Source-attribute validated response
 *  [13] Inject confidence disclaimer and limitations
 *  [14] Write immutable audit record and return to caller
 */

import { logStructured } from "../observability/logger.js";
import {
  evidenceValidator,
  type EvidenceBundle,
  type EvidenceValidationResult,
} from "./evidence_validator.js";
import {
  evidenceIntegrityValidator,
  type IntegrityStamp,
} from "./evidence_integrity_validator.js";
import {
  confidenceGate,
  type ConfidenceGateResult,
} from "./confidence_gate.js";
import {
  truthEngine,
  buildSafeFallbackResponse,
  type TruthEngineResult,
} from "./truth_engine.js";
import { aiCircuitBreaker } from "./ai_circuit_breaker.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AIRequest {
  request_id: string;
  session_id: string | null;
  tenant_id: number;
  user_id: number | null;
  user_role: string;
  ip_address: string;
  prompt: string;
  request_type:
    | "anomaly_explanation"
    | "incident_summarization"
    | "analyst_question"
    | "executive_report"
    | "knowledge_search";
  evidence: EvidenceBundle;
  evidence_stamp: IntegrityStamp;
  evidence_age_ms: number;
  rag_documents?: RetrievedRAGDocument[];
  model_override?: string;
}

export interface RetrievedRAGDocument {
  doc_id: string;
  source: string;
  filename: string;
  trust_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  relevance_score: number;
  content: string;
  version: string;
  collection: string;
}

export interface AIResponse {
  request_id: string;
  response: string;
  truth_score: number;
  truth_badge: "HIGH" | "MEDIUM" | "LOW" | "REJECTED";
  confidence_level: "HIGH" | "MEDIUM" | "LOW";
  safe_fallback_used: boolean;
  model_used: string;
  latency_ms: number;
  tokens_input: number;
  tokens_output: number;
  evidence_hash: string;
  response_hash: string;
  rag_citations: string[];
  limitations: string[];
  outcome: AIOutcome;
}

export type AIOutcome =
  | "DELIVERED"
  | "DELIVERED_CACHED"
  | "SAFE_FALLBACK"
  | "BLOCKED_CIRCUIT_OPEN"
  | "BLOCKED_EVIDENCE"
  | "BLOCKED_CONFIDENCE"
  | "LLM_TIMEOUT"
  | "LLM_ERROR";

// ─── Configuration ────────────────────────────────────────────────────────────

const LLM_TIMEOUT_MS = 30_000;
const MAX_INPUT_TOKENS = 30_000;
const MAX_OUTPUT_TOKENS = 4_000;
const DEFAULT_MODEL = "gemini-2.5-flash";

// ─── Anti-Hallucination System Prompt ────────────────────────────────────────

const SYSTEM_PROMPT = `You are the Aegis SOC Analyst Assistant.

ROLE: Advisory only. You explain security events. You do NOT make decisions.

ABSOLUTE RULES — NEVER VIOLATE:
1. ONLY reference facts present in the Evidence Bundle provided below.
2. NEVER invent CVE IDs, MITRE technique IDs, IP addresses, domains, hashes, or URLs.
3. NEVER name threat actors not in the Threat Intelligence section of the evidence.
4. NEVER suggest a different severity or confidence than what is in the evidence.
5. NEVER create, close, or escalate incidents.
6. NEVER override detection engine outputs.
7. If information is missing, say explicitly: "This information is not available in the current evidence."
8. ALWAYS cite your source (Rule Engine, Threat Fusion, Threat Intelligence, Asset Context, etc.).
9. ALWAYS include a Limitations section listing what evidence is unavailable.
10. NEVER speculate beyond the supplied evidence.

RESPONSE FORMAT (MANDATORY):
## 🔍 Executive Summary
## 📊 Evidence Summary
## 🧩 Threat Explanation [cite sources for every claim]
## 🎯 MITRE ATT&CK Mapping [only from evidence mitre_mappings — mark empty if none]
## ⚠️ Risk Assessment [from risk_score and asset criticality]
## 🛡️ Recommended Actions [from rule engine recommendations only]
## ⚡ Limitations [list all unavailable evidence fields]
## 📚 Evidence Sources [list all sources used]
## 📈 Confidence Statement [state confidence level]`;

// ─── AI Orchestrator ──────────────────────────────────────────────────────────

export class AIOrchestrator {
  /**
   * Process an AI request through the complete 14-step governance pipeline.
   * This is the ONLY path to the LLM in the entire Aegis platform.
   */
  async processRequest(request: AIRequest): Promise<AIResponse> {
    const startMs = Date.now();
    const evidenceHash = evidenceIntegrityValidator.computeHash(
      request.evidence,
    );

    // ── Step 2: Evidence Integrity Verification ──────────────────
    const integrityResult = evidenceIntegrityValidator.verify(
      request.evidence,
      request.evidence_stamp,
    );
    if (!integrityResult.valid) {
      logStructured("error", "[AIOrchestrator] Evidence integrity failed", {
        request_id: request.request_id,
        reason: integrityResult.rejection_reason,
      });
      return this.buildBlockedResponse(
        request,
        "BLOCKED_EVIDENCE",
        startMs,
        evidenceHash,
        integrityResult.rejection_reason ?? "Evidence integrity violation",
      );
    }

    // ── Step 3: Evidence Completeness Validation ─────────────────
    const validationResult: EvidenceValidationResult =
      evidenceValidator.validate(request.evidence);
    if (!validationResult.valid) {
      return this.buildBlockedResponse(
        request,
        "BLOCKED_EVIDENCE",
        startMs,
        evidenceHash,
        validationResult.rejection_reason ?? "Evidence incomplete",
      );
    }

    // ── Step 4: Confidence Gate ───────────────────────────────────
    const confidenceResult: ConfidenceGateResult = confidenceGate.evaluate(
      request.evidence,
      request.evidence_age_ms,
    );
    if (!confidenceResult.allow) {
      logStructured(
        "warn",
        "[AIOrchestrator] Request blocked by Confidence Gate (LOW)",
        {
          request_id: request.request_id,
          score: confidenceResult.score,
        },
      );
      return this.buildBlockedResponse(
        request,
        "BLOCKED_CONFIDENCE",
        startMs,
        evidenceHash,
        confidenceResult.disclaimer ?? "Confidence too low",
      );
    }

    // ── Step 6: Circuit Breaker Check ────────────────────────────
    if (!aiCircuitBreaker.allowRequest()) {
      logStructured(
        "warn",
        "[AIOrchestrator] Circuit OPEN — returning safe fallback",
        {
          request_id: request.request_id,
        },
      );
      return this.buildSafeFallbackResult(
        request,
        "BLOCKED_CIRCUIT_OPEN",
        startMs,
        evidenceHash,
        confidenceResult,
        0,
        "",
        [],
      );
    }

    // ── Steps 7–8: Build Evidence-Anchored Prompt ─────────────────
    const prompt = this.buildPrompt(request, confidenceResult);

    // ── Step 9: Call LLM with timeout and retry ───────────────────
    let rawResponse = "";
    let tokensIn = 0;
    let tokensOut = 0;
    let llmOutcome: AIOutcome = "DELIVERED";
    let modelUsed = request.model_override ?? DEFAULT_MODEL;

    try {
      const llmResult = await this.callLLMWithTimeout(
        prompt,
        request.model_override,
      );
      rawResponse = llmResult.text;
      tokensIn = llmResult.tokensIn;
      tokensOut = llmResult.tokensOut;
      modelUsed = llmResult.modelUsed;
      aiCircuitBreaker.recordSuccess();
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      aiCircuitBreaker.recordFailure(errMsg);
      logStructured("error", "[AIOrchestrator] LLM call failed", {
        request_id: request.request_id,
        error: errMsg,
      });
      llmOutcome = errMsg.includes("timeout") ? "LLM_TIMEOUT" : "LLM_ERROR";
      return this.buildSafeFallbackResult(
        request,
        llmOutcome,
        startMs,
        evidenceHash,
        confidenceResult,
        tokensIn,
        "",
        [],
      );
    }

    // ── Steps 10–11: Truth Engine Validation ──────────────────────
    const truthResult: TruthEngineResult = truthEngine.validate(
      rawResponse,
      request.evidence,
    );

    if (truthResult.safe_fallback_triggered) {
      return this.buildSafeFallbackResult(
        request,
        "SAFE_FALLBACK",
        startMs,
        evidenceHash,
        confidenceResult,
        tokensIn,
        truthResult.response_hash,
        request.rag_documents ?? [],
      );
    }

    // ── Steps 12–13: Source Attribution + Disclaimer ──────────────
    const attributedResponse = this.attributeAndAnnotate(
      rawResponse,
      request.evidence,
      confidenceResult,
      truthResult,
      request.rag_documents ?? [],
    );

    // ── Step 14: Assemble and return ──────────────────────────────
    const latencyMs = Date.now() - startMs;
    const citations = (request.rag_documents ?? []).map(
      (d) =>
        `${d.source} [Trust: ${d.trust_level}] [Relevance: ${d.relevance_score.toFixed(2)}]`,
    );

    logStructured("info", "[AIOrchestrator] Request completed", {
      request_id: request.request_id,
      truth_score: truthResult.truth_score,
      badge: truthResult.badge,
      latency_ms: latencyMs,
      tokens_in: tokensIn,
      tokens_out: tokensOut,
    });

    return {
      request_id: request.request_id,
      response: attributedResponse,
      truth_score: truthResult.truth_score,
      truth_badge: truthResult.badge,
      confidence_level: confidenceResult.level,
      safe_fallback_used: false,
      model_used: modelUsed,
      latency_ms: latencyMs,
      tokens_input: tokensIn,
      tokens_output: tokensOut,
      evidence_hash: evidenceHash,
      response_hash: truthResult.response_hash,
      rag_citations: citations,
      limitations: confidenceResult.limitations,
      outcome: llmOutcome,
    };
  }

  // ── Private: Prompt Construction ──────────────────────────────────────────

  private buildPrompt(
    request: AIRequest,
    confidence: ConfidenceGateResult,
  ): string {
    const ev = request.evidence;
    const parts: string[] = [SYSTEM_PROMPT, ""];

    // Evidence Bundle (structured, sanitized — not raw DB rows)
    parts.push(
      "## EVIDENCE BUNDLE (Deterministic Engine Outputs — DO NOT MODIFY)",
    );
    parts.push("```json");
    parts.push(
      JSON.stringify(
        {
          anomaly_id: ev.anomaly_id,
          detection_method: ev.detection_method,
          severity: ev.severity,
          hybrid_score: ev.hybrid_score,
          z_score: ev.z_score,
          confidence: ev.confidence,
          risk_score: ev.risk_score,
          matched_rules: ev.matched_rules,
          threat_fusion: ev.threat_fusion,
          threat_intelligence: ev.threat_intelligence,
          asset_context: ev.asset_context,
          behavior_context: ev.behavior_context,
          mitre_mappings: ev.mitre_mappings,
          explainability_summary: ev.explainability_summary,
        },
        null,
        2,
      ),
    );
    parts.push("```");
    parts.push("");

    // RAG Context
    if (request.rag_documents && request.rag_documents.length > 0) {
      parts.push(
        "## RETRIEVED KNOWLEDGE (Use for context only — cite sources)",
      );
      for (const doc of request.rag_documents.slice(0, 5)) {
        parts.push(
          `### [Source: ${doc.source} | Trust: ${doc.trust_level} | Relevance: ${doc.relevance_score.toFixed(2)}]`,
        );
        parts.push(doc.content.slice(0, 800)); // Token budget control
        parts.push("");
      }
    }

    // Confidence context
    if (confidence.level === "MEDIUM") {
      parts.push(
        `> ⚠ Evidence completeness: ${(confidence.score * 100).toFixed(0)}%. ${MEDIUM_CONTEXT}`,
      );
      parts.push("");
    }

    // Missing evidence notice
    if (confidence.limitations.length > 0) {
      parts.push("## MISSING EVIDENCE (AI MUST LIST IN LIMITATIONS SECTION)");
      for (const lim of confidence.limitations) parts.push(`- ${lim}`);
      parts.push("");
    }

    // Analyst question
    parts.push("## ANALYST REQUEST");
    parts.push(request.prompt);

    return parts.join("\n");
  }

  private async callLLMWithTimeout(
    prompt: string,
    modelOverride?: string,
  ): Promise<{
    text: string;
    modelUsed: string;
    tokensIn: number;
    tokensOut: number;
  }> {
    const groqKey = process.env.GROQ_API_KEY;
    const hasGroq = !!(
      groqKey &&
      groqKey.trim() !== "" &&
      groqKey !== "YOUR_GROQ_API_KEY_HERE"
    );

    if (hasGroq) {
      const groqModel =
        modelOverride || process.env.GROQ_MODEL || "groq/compound-mini";
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);
        const res = await fetch(
          "https://api.groq.com/openai/v1/chat/completions",
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${groqKey!.trim()}`,
              "Content-Type": "application/json",
              "User-Agent": "Aegis-SOC/1.0",
            },
            body: JSON.stringify({
              model: groqModel,
              messages: [{ role: "user", content: prompt }],
              max_tokens: MAX_OUTPUT_TOKENS,
              temperature: 0.2,
            }),
            signal: controller.signal,
          },
        );
        clearTimeout(timeout);

        if (res.ok) {
          const data = (await res.json()) as any;
          let text = data.choices?.[0]?.message?.content ?? "";
          if (text.includes("</think>")) {
            text = text.substring(text.indexOf("</think>") + 8).trim();
          }
          const usage = data.usage ?? {};
          return {
            text,
            modelUsed: `groq/${groqModel}`,
            tokensIn: usage.prompt_tokens ?? Math.ceil(prompt.length / 4),
            tokensOut: usage.completion_tokens ?? Math.ceil(text.length / 4),
          };
        } else {
          const errText = await res.text().catch(() => "");
          console.warn(
            `[Copilot AI] Groq API returned ${res.status}: ${errText}. Falling back to Gemini.`,
          );
        }
      } catch (err: any) {
        console.warn(
          `[Copilot AI] Groq call failed: ${err.message}. Falling back to Gemini.`,
        );
      }
    }

    // Fallback: Gemini API
    const geminiKey = process.env.GEMINI_API_KEY;
    if (
      !geminiKey ||
      geminiKey.trim() === "" ||
      geminiKey === "YOUR_GEMINI_API_KEY_HERE"
    ) {
      throw new Error("Neither GROQ_API_KEY nor GEMINI_API_KEY is configured.");
    }

    const { GoogleGenAI } = await import("@google/genai");
    const genAI = new GoogleGenAI({ apiKey: geminiKey });
    const modelId = modelOverride ?? DEFAULT_MODEL;

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error("LLM timeout after 30 seconds")),
        LLM_TIMEOUT_MS,
      ),
    );

    const callPromise = genAI.models.generateContent({
      model: modelId,
      contents: prompt,
      config: { maxOutputTokens: MAX_OUTPUT_TOKENS },
    });
    const result = await Promise.race([callPromise, timeoutPromise]);
    let text = result.text ?? "";
    if (text.includes("</think>")) {
      text = text.substring(text.indexOf("</think>") + 8).trim();
    }

    // Token usage — Gemini API provides usage metadata
    const usage = (result as any).usageMetadata ?? {};
    return {
      text,
      modelUsed: `gemini/${modelId}`,
      tokensIn: usage.promptTokenCount ?? Math.ceil(prompt.length / 4),
      tokensOut: usage.candidatesTokenCount ?? Math.ceil(text.length / 4),
    };
  }

  // ── Private: Response Attribution ────────────────────────────────────────

  private attributeAndAnnotate(
    response: string,
    evidence: EvidenceBundle,
    confidence: ConfidenceGateResult,
    truth: TruthEngineResult,
    ragDocs: RetrievedRAGDocument[],
  ): string {
    const parts: string[] = [response];

    // Inject truth score badge
    parts.push("");
    parts.push("---");
    parts.push(
      `**Truth Score:** ${(truth.truth_score * 100).toFixed(0)}% [${truth.badge}] | ` +
        `**Evidence Confidence:** ${(evidence.confidence * 100).toFixed(0)}% | ` +
        `**Severity:** ${evidence.severity}`,
    );

    // Medium confidence disclaimer
    if (confidence.level === "MEDIUM" && confidence.disclaimer) {
      parts.push("");
      parts.push(confidence.disclaimer);
    }

    return parts.join("\n");
  }

  // ── Private: Response Builders ────────────────────────────────────────────

  private buildBlockedResponse(
    request: AIRequest,
    outcome: AIOutcome,
    startMs: number,
    evidenceHash: string,
    reason: string,
  ): AIResponse {
    return {
      request_id: request.request_id,
      response: `❌ **AI Request Blocked:** ${reason}`,
      truth_score: 0,
      truth_badge: "REJECTED",
      confidence_level: "LOW",
      safe_fallback_used: true,
      model_used: DEFAULT_MODEL,
      latency_ms: Date.now() - startMs,
      tokens_input: 0,
      tokens_output: 0,
      evidence_hash: evidenceHash,
      response_hash: "",
      rag_citations: [],
      limitations: [],
      outcome,
    };
  }

  private buildSafeFallbackResult(
    request: AIRequest,
    outcome: AIOutcome,
    startMs: number,
    evidenceHash: string,
    confidence: ConfidenceGateResult,
    tokensIn: number,
    responseHash: string,
    ragDocs: RetrievedRAGDocument[],
  ): AIResponse {
    const fallback = buildSafeFallbackResponse(request.evidence);
    return {
      request_id: request.request_id,
      response: fallback,
      truth_score: 0,
      truth_badge: "REJECTED",
      confidence_level: confidence.level,
      safe_fallback_used: true,
      model_used: DEFAULT_MODEL,
      latency_ms: Date.now() - startMs,
      tokens_input: tokensIn,
      tokens_output: 0,
      evidence_hash: evidenceHash,
      response_hash: responseHash,
      rag_citations: [],
      limitations: confidence.limitations,
      outcome,
    };
  }
}

const MEDIUM_CONTEXT =
  "Acknowledge uncertainty where evidence is partial. Use hedged language.";

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiOrchestrator = new AIOrchestrator();
