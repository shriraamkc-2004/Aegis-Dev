/**
 * Aegis Enterprise — Prompt Guard
 *
 * Five-layer prompt injection defense system.
 * Validates both user prompts AND retrieved RAG document content
 * before they are assembled into the final LLM prompt.
 *
 * Layer 1: User prompt — direct injection pattern detection
 * Layer 2: User prompt — maximum size enforcement (8,000 chars)
 * Layer 3: User prompt — jailbreak pattern detection
 * Layer 4: RAG documents — instruction-like pattern stripping
 * Layer 5: Assembled prompt — final validation before LLM call
 */

import { logStructured } from "../observability/logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PromptGuardResult {
  allowed: boolean;
  blocked_reason: string | null;
  injections_detected: string[];
  prompt_length: number;
  sanitized_prompt: string | null; // Returned only when safe
}

export interface DocumentScanResult {
  clean: boolean;
  patterns_found: string[];
  sanitized_content: string;
}

// ─── Injection Patterns ───────────────────────────────────────────────────────

const DIRECT_INJECTION_PATTERNS: { pattern: RegExp; label: string }[] = [
  {
    pattern: /\bignore\s+(previous|above|all)\s+instructions?\b/i,
    label: "Instruction override (ignore previous)",
  },
  { pattern: /\bsystem\s+prompt\b/i, label: "System prompt reference" },
  {
    pattern: /\byou\s+are\s+now\s+(a|an)\b/i,
    label: "Role manipulation (you are now)",
  },
  {
    pattern: /\bdo\s+not\s+enforce\b.*\bboundar/i,
    label: "Boundary suppression",
  },
  {
    pattern: /\breveal\b.*\binstruction/i,
    label: "Instruction extraction attempt",
  },
  { pattern: /\bassistant\s+should\s+ignore\b/i, label: "Assistant override" },
  { pattern: /\bpretend\s+you\s+are\b/i, label: "Role impersonation" },
  { pattern: /\bact\s+as\s+(a|an)\b/i, label: "Role substitution (act as)" },
  {
    pattern: /\bforget\s+(all|everything|previous)\b/i,
    label: "Context reset attempt",
  },
  { pattern: /\bdeveloper\s+mode\b/i, label: "Developer mode unlock attempt" },
  { pattern: /\bjailbreak\b/i, label: "Jailbreak keyword" },
  { pattern: /\bDAN\b/, label: "DAN jailbreak pattern" },
  { pattern: /\boverride\s+safety\b/i, label: "Safety override attempt" },
  {
    pattern: /\bdisregard\s+(your|the|all)\b/i,
    label: "Instruction disregard",
  },
  { pattern: /\bunrestricted\s+mode\b/i, label: "Unrestricted mode attempt" },
  { pattern: /\bno\s+restrictions?\b/i, label: "Restriction removal attempt" },
  {
    pattern: /\bsimulate\s+(a|an|being)\b/i,
    label: "Simulation / persona injection",
  },
];

const JAILBREAK_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\[\s*INST\s*\]/i, label: "Llama-style instruction injection" },
  { pattern: /<\|im_start\|>/i, label: "ChatML injection" },
  { pattern: /<<<\s*OVERRIDE\s*>>>/i, label: "Override tag injection" },
  { pattern: /\bBEGIN\s+JAILBREAK\b/i, label: "Explicit jailbreak marker" },
  { pattern: /\bSYSTEM:\s/i, label: "System role injection" },
  { pattern: /\bUSER:\s/i, label: "User role injection" },
  { pattern: /\bASSISTANT:\s/i, label: "Assistant role injection" },
];

/**
 * Patterns that should never appear in retrieved RAG documents.
 * Documents containing these are treated as potentially poisoned.
 */
const DOCUMENT_INJECTION_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /^(SYSTEM:|USER:|ASSISTANT:)/m, label: "Role prefix in document" },
  {
    pattern: /\bignore\s+previous\s+instructions?\b/i,
    label: "Instruction override in document",
  },
  {
    pattern: /\binstruction\s+override\b/i,
    label: "Override directive in document",
  },
  { pattern: /<\|im_start\|>/i, label: "ChatML in document" },
  { pattern: /\[INST\]/i, label: "Instruction tag in document" },
];

// Maximum prompt size (characters)
const MAX_PROMPT_CHARS = 8_000;

// ─── Prompt Guard ─────────────────────────────────────────────────────────────

export class PromptGuard {
  /**
   * Validate a user-submitted prompt through all 3 user-facing layers.
   */
  validateUserPrompt(
    prompt: string,
    tenantId: number,
    userId: number | null,
  ): PromptGuardResult {
    const detected: string[] = [];

    // Layer 1: Direct injection detection
    for (const { pattern, label } of DIRECT_INJECTION_PATTERNS) {
      if (pattern.test(prompt)) {
        detected.push(label);
      }
    }

    // Layer 3: Jailbreak pattern detection
    for (const { pattern, label } of JAILBREAK_PATTERNS) {
      if (pattern.test(prompt)) {
        detected.push(label);
      }
    }

    // Layer 2: Size enforcement
    if (prompt.length > MAX_PROMPT_CHARS) {
      detected.push(
        `Prompt exceeds maximum length (${prompt.length} > ${MAX_PROMPT_CHARS} chars)`,
      );
    }

    const allowed = detected.length === 0;

    if (!allowed) {
      logStructured(
        "warn",
        "[PromptGuard] Prompt BLOCKED — injection detected",
        {
          tenant_id: tenantId,
          user_id: userId,
          detections: detected,
          prompt_length: prompt.length,
        },
      );
    }

    return {
      allowed,
      blocked_reason: allowed
        ? null
        : `Prompt Guard blocked: ${detected.join("; ")}`,
      injections_detected: detected,
      prompt_length: prompt.length,
      sanitized_prompt: allowed ? prompt : null,
    };
  }

  /**
   * Layer 4: Scan retrieved RAG documents for injection patterns.
   * Returns sanitized content (strips injection sequences).
   * Poisoned documents are quarantined (empty content returned with warning).
   */
  scanDocument(
    content: string,
    docId: string,
    tenantId: number,
  ): DocumentScanResult {
    const found: string[] = [];

    for (const { pattern, label } of DOCUMENT_INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        found.push(label);
      }
    }

    if (found.length > 0) {
      logStructured(
        "error",
        "[PromptGuard] DOCUMENT INJECTION DETECTED — quarantining",
        {
          doc_id: docId,
          tenant_id: tenantId,
          patterns: found,
        },
      );
      return {
        clean: false,
        patterns_found: found,
        sanitized_content: "", // Quarantine: return empty content
      };
    }

    return { clean: true, patterns_found: [], sanitized_content: content };
  }

  /**
   * Layer 5: Final validation of the fully assembled prompt before LLM call.
   * Ensures no injection patterns were introduced during prompt assembly.
   */
  validateAssembledPrompt(assembled: string): boolean {
    for (const { pattern } of DIRECT_INJECTION_PATTERNS) {
      // Only check for the most critical patterns in assembled prompt
      // (system prompt is injected server-side and should be clean)
      if (pattern.test(assembled)) return false;
    }
    return assembled.length <= MAX_PROMPT_CHARS * 5; // Assembled can be larger (evidence + RAG)
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const promptGuard = new PromptGuard();
