/**
 * Aegis Enterprise — Source Attributor
 *
 * Annotates every AI response claim with its deterministic source engine.
 * Every factual statement in an AI response must trace back to a source
 * from the EvidenceBundle — this module creates that traceability.
 *
 * Adds source annotations, marks unverified claims with [UNVERIFIED],
 * and appends a structured Evidence Sources section to the response.
 */

import type { EvidenceBundle } from "./evidence_validator.js";
import type { TruthEngineResult } from "./truth_engine.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SourceAnnotation {
  claim: string;
  source: string;
  verified: boolean;
}

export interface AttributionResult {
  annotated_response: string;
  source_annotations: SourceAnnotation[];
  sources_used: string[];
}

// ─── Source Attributor ────────────────────────────────────────────────────────

export class SourceAttributor {
  /**
   * Annotate a validated AI response with source information.
   * Appends a structured Evidence Sources section.
   */
  attribute(
    validatedResponse: string,
    evidence: EvidenceBundle,
    truthResult: TruthEngineResult,
    ragDocuments: Array<{
      source: string;
      trust_level: string;
      relevance_score: number;
      filename: string;
    }>,
  ): AttributionResult {
    const sourcesUsed: string[] = [];
    const annotations: SourceAnnotation[] = [];

    // Collect all deterministic sources actually referenced in evidence
    if (evidence.matched_rules.filter((r) => r.matched).length > 0) {
      sourcesUsed.push("Rule Engine");
    }
    if (evidence.threat_fusion !== null) {
      sourcesUsed.push("Threat Fusion Engine");
    }
    if (evidence.threat_intelligence.length > 0) {
      const tiSources = [
        ...new Set(evidence.threat_intelligence.map((t) => t.source)),
      ];
      for (const s of tiSources) sourcesUsed.push(`Threat Intelligence (${s})`);
    }
    if (evidence.asset_context !== null) {
      sourcesUsed.push("Asset Context Engine");
    }
    if (evidence.behavior_context !== null) {
      sourcesUsed.push("Behavior Engine (60s window)");
    }
    if (evidence.mitre_mappings.length > 0) {
      const mitreSource = [
        ...new Set(evidence.mitre_mappings.map((m) => m.source)),
      ];
      sourcesUsed.push(`MITRE ATT&CK (via ${mitreSource.join(", ")})`);
    }
    sourcesUsed.push("Explainability Engine");

    // RAG document sources
    for (const doc of ragDocuments) {
      sourcesUsed.push(
        `Knowledge Base: ${doc.source} [Trust: ${doc.trust_level}] [Relevance: ${doc.relevance_score.toFixed(2)}]`,
      );
    }

    // Build claim annotations from Truth Engine results
    for (const claim of truthResult.claims) {
      annotations.push({
        claim: claim.value,
        source: claim.verification_source ?? "UNVERIFIED",
        verified: claim.verified,
      });
    }

    // Append Evidence Sources section to response
    const sourcesSection = this.buildSourcesSection(
      evidence,
      ragDocuments,
      sourcesUsed,
      truthResult,
    );

    const annotatedResponse = `${validatedResponse}\n\n${sourcesSection}`;

    return {
      annotated_response: annotatedResponse,
      source_annotations: annotations,
      sources_used: sourcesUsed,
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private buildSourcesSection(
    evidence: EvidenceBundle,
    ragDocs: Array<{
      source: string;
      trust_level: string;
      relevance_score: number;
      filename: string;
    }>,
    sourcesUsed: string[],
    truth: TruthEngineResult,
  ): string {
    const lines: string[] = ["---", "### 📚 Evidence Sources & Attribution"];

    // Deterministic engines
    lines.push("**Deterministic Engines:**");
    const ruleMatches = evidence.matched_rules.filter((r) => r.matched);
    if (ruleMatches.length > 0) {
      lines.push(
        `- **Rule Engine:** ${ruleMatches.map((r) => r.rule_name).join(", ")}`,
      );
    } else {
      lines.push("- **Rule Engine:** No rules matched");
    }

    if (evidence.threat_fusion) {
      lines.push(
        `- **Threat Fusion Engine:** ${evidence.threat_fusion.possible_threat ?? "Classification available"}`,
      );
    } else {
      lines.push("- **Threat Fusion Engine:** Not available");
    }

    if (evidence.threat_intelligence.length > 0) {
      lines.push(
        `- **Threat Intelligence:** ${evidence.threat_intelligence.length} indicator(s) from ${[...new Set(evidence.threat_intelligence.map((t) => t.source))].join(", ")}`,
      );
    } else {
      lines.push("- **Threat Intelligence:** Not available");
    }

    if (evidence.asset_context) {
      lines.push(
        `- **Asset Context:** ${evidence.asset_context.hostname ?? evidence.asset_context.ip_address ?? "Asset identified"} [Criticality: ${evidence.asset_context.criticality ?? "Unknown"}]`,
      );
    } else {
      lines.push("- **Asset Context:** Not available");
    }

    if (evidence.behavior_context) {
      lines.push(
        `- **Behavior Engine:** 60-second window — ${evidence.behavior_context.events_per_second.toFixed(1)} events/sec`,
      );
    } else {
      lines.push("- **Behavior Engine:** Not available");
    }

    lines.push(
      `- **Explainability Engine:** Score=${(evidence.hybrid_score * 100).toFixed(0)}% | Severity=${evidence.severity}`,
    );

    // Knowledge base sources
    if (ragDocs.length > 0) {
      lines.push("");
      lines.push("**Knowledge Base:**");
      for (const doc of ragDocs) {
        lines.push(
          `- ${doc.source} | ${doc.filename} | Trust: ${doc.trust_level} | Relevance: ${doc.relevance_score.toFixed(2)}`,
        );
      }
    }

    // Truth engine summary
    lines.push("");
    lines.push(
      `**Verification:** ${truth.verified_count}/${truth.total_claims} claims verified | Truth Score: ${(truth.truth_score * 100).toFixed(0)}%`,
    );

    return lines.join("\n");
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const sourceAttributor = new SourceAttributor();
