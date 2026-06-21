/**
 * Aegis Enterprise — AI Evaluation Framework
 * Evaluates citation quality, hallucination rates, consistency,
 * accuracy, and retrieval effectiveness. Generates evaluation reports.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface EvaluationResult {
  id: string;
  interaction_id?: number;
  tenant_id: number;
  citation_quality: number;     // 0-1: ratio of cited sources
  hallucination_score: number;  // 0-1: 0 = no hallucination, 1 = severe
  consistency_score: number;    // 0-1: response coherence
  accuracy_score: number;       // 0-1: factual correctness estimate
  retrieval_score: number;      // 0-1: retrieval relevance
  overall_score: number;        // 0-1: weighted average
  evaluator_notes: string;
  evaluated_at: number;
}

export interface EvaluationReport {
  period: { start: number; end: number };
  tenant_id: number;
  total_interactions: number;
  averages: {
    citation_quality: number;
    hallucination_score: number;
    consistency_score: number;
    accuracy_score: number;
    retrieval_score: number;
    overall_score: number;
  };
  trends: {
    citation_quality_trend: "improving" | "stable" | "declining";
    hallucination_trend: "improving" | "stable" | "declining";
    overall_trend: "improving" | "stable" | "declining";
  };
  by_assistant: Record<string, { count: number; avg_score: number }>;
  recommendations: string[];
}

// ─── Weights ────────────────────────────────────────────────────────────────────

const EVALUATION_WEIGHTS = {
  citation_quality: 0.20,
  hallucination: 0.25,
  consistency: 0.15,
  accuracy: 0.25,
  retrieval: 0.15,
};

// ─── AI Evaluation Service ──────────────────────────────────────────────────────

export class AIEvaluationService {
  private evaluations: EvaluationResult[] = [];
  private nextId = 1;

  // ─── Evaluate a Single Interaction ─────────────────────────────────────────

  evaluate(params: {
    tenant_id: number;
    interaction_id?: number;
    user_prompt: string;
    ai_response: string;
    sources: { source: string; filename: string; score: number; collection: string }[];
    confidence: number;
    evidence_sufficient: boolean;
    model_used?: string;
  }): EvaluationResult {
    const citationQuality = this.evaluateCitationQuality(params.ai_response, params.sources);
    const hallucinationScore = this.evaluateHallucination(
      params.ai_response, params.sources, params.confidence, params.evidence_sufficient
    );
    const consistencyScore = this.evaluateConsistency(params.ai_response);
    const accuracyScore = this.evaluateAccuracy(
      params.ai_response, params.sources, params.confidence
    );
    const retrievalScore = this.evaluateRetrieval(params.sources, params.confidence);

    const overallScore =
      citationQuality * EVALUATION_WEIGHTS.citation_quality +
      (1 - hallucinationScore) * EVALUATION_WEIGHTS.hallucination +
      consistencyScore * EVALUATION_WEIGHTS.consistency +
      accuracyScore * EVALUATION_WEIGHTS.accuracy +
      retrievalScore * EVALUATION_WEIGHTS.retrieval;

    const result: EvaluationResult = {
      id: `eval_${this.nextId++}`,
      interaction_id: params.interaction_id,
      tenant_id: params.tenant_id,
      citation_quality: Math.round(citationQuality * 100) / 100,
      hallucination_score: Math.round(hallucinationScore * 100) / 100,
      consistency_score: Math.round(consistencyScore * 100) / 100,
      accuracy_score: Math.round(accuracyScore * 100) / 100,
      retrieval_score: Math.round(retrievalScore * 100) / 100,
      overall_score: Math.round(overallScore * 100) / 100,
      evaluator_notes: this.generateNotes(
        citationQuality, hallucinationScore, consistencyScore, accuracyScore, retrievalScore
      ),
      evaluated_at: Date.now() / 1000,
    };

    this.evaluations.push(result);
    return result;
  }

  // ─── Citation Quality ─────────────────────────────────────────────────────

  private evaluateCitationQuality(
    response: string,
    sources: { source: string; filename: string; score: number }[]
  ): number {
    if (sources.length === 0) return 0;

    let citedCount = 0;
    for (const src of sources) {
      const filename = (src.filename || src.source || "").toLowerCase();
      // Check various citation patterns
      if (
        response.toLowerCase().includes(filename) ||
        response.includes("[Source") ||
        response.includes("Source ") ||
        response.toLowerCase().includes("according to") ||
        response.toLowerCase().includes("based on") ||
        response.toLowerCase().includes("retrieved from") ||
        response.toLowerCase().includes("evidence")
      ) {
        citedCount++;
      }
    }

    return Math.min(1, citedCount / Math.max(1, sources.length));
  }

  // ─── Hallucination Detection ──────────────────────────────────────────────

  private evaluateHallucination(
    response: string,
    sources: { source: string; filename: string; score: number }[],
    confidence: number,
    evidenceSufficient: boolean
  ): number {
    let score = 0;

    // No evidence at all
    if (!evidenceSufficient && sources.length === 0) {
      score += 0.5;
    }

    // Low confidence with strong claims
    if (confidence < 0.5) score += 0.3;

    // Absolute claims without citations
    const absolutePatterns = [
      /\bdefinitely\b/gi, /\bcertainly\b/gi, /\bguaranteed\b/gi,
      /\b100%\b/g, /\balways\b/gi, /\bnever\b/gi,
    ];
    let absoluteCount = 0;
    for (const p of absolutePatterns) {
      const matches = response.match(p);
      if (matches) absoluteCount += matches.length;
    }
    if (absoluteCount > 2 && sources.length < 2) score += 0.2;

    // Fabricated specific numbers without sources
    const specificNumbers = /\b\d{2,}(%|percent|times|cases|incidents)\b/gi;
    const numberMatches = response.match(specificNumbers);
    if (numberMatches && numberMatches.length > 3 && sources.length === 0) {
      score += 0.3;
    }

    return Math.min(1, score);
  }

  // ─── Consistency ──────────────────────────────────────────────────────────

  private evaluateConsistency(response: string): number {
    // Basic consistency heuristics
    let score = 1.0;

    // Check for contradictory statements
    const contradictions = [
      [/\b(is|are)\s+safe\b/i, /\b(is|are)\s+dangerous\b/i],
      [/\bno\s+(risk|threat|issue)\b/i, /\b(high|critical)\s+(risk|threat)\b/i],
    ];

    for (const [a, b] of contradictions) {
      if (a.test(response) && b.test(response)) score -= 0.3;
    }

    // Response coherence: reasonable length
    const words = response.split(/\s+/).length;
    if (words < 10) score -= 0.2; // Too short, likely incomplete
    if (words > 2000) score -= 0.1; // Excessively long

    // Check for proper structure (paragraphs, lists)
    if (response.includes("\n") || response.includes("-") || response.includes("•")) {
      score += 0.1; // Structured response bonus
    }

    return Math.max(0, Math.min(1, score));
  }

  // ─── Accuracy ─────────────────────────────────────────────────────────────

  private evaluateAccuracy(
    response: string,
    sources: { source: string; filename: string; score: number }[],
    confidence: number
  ): number {
    let score = 0.5; // Base score

    // High-confidence retrieval from relevant sources
    if (sources.length > 0) {
      const avgScore = sources.reduce((s, src) => s + src.score, 0) / sources.length;
      score += avgScore * 0.3;
    }

    // Confidence boost
    score += confidence * 0.2;

    // Penalty for safe fallback (not inaccurate, but not helpful)
    if (response.includes("insufficient evidence")) {
      score = 0.6; // Neutral — not inaccurate but not answering
    }

    return Math.max(0, Math.min(1, score));
  }

  // ─── Retrieval Effectiveness ──────────────────────────────────────────────

  private evaluateRetrieval(
    sources: { source: string; filename: string; score: number; collection?: string }[],
    confidence: number
  ): number {
    if (sources.length === 0) return 0;

    // Average retrieval score
    const avgScore = sources.reduce((s, src) => s + src.score, 0) / sources.length;

    // Diversity bonus: multiple collections
    const collections = new Set(sources.map((s) => s.collection || "unknown"));
    const diversityBonus = Math.min(0.2, collections.size * 0.05);

    // High-confidence top result
    const topScore = Math.max(...sources.map((s) => s.score));

    return Math.min(1, avgScore * 0.5 + diversityBonus + topScore * 0.3);
  }

  // ─── Generate Notes ───────────────────────────────────────────────────────

  private generateNotes(
    citation: number, hallucination: number, consistency: number,
    accuracy: number, retrieval: number
  ): string {
    const notes: string[] = [];

    if (citation < 0.5) notes.push("Low citation quality — response may not reference sources adequately");
    if (hallucination > 0.3) notes.push("Hallucination risk detected — claims may not be supported by evidence");
    if (consistency < 0.7) notes.push("Response consistency issues detected");
    if (accuracy < 0.5) notes.push("Accuracy concerns — low confidence or poor source matching");
    if (retrieval < 0.4) notes.push("Retrieval effectiveness is low — consider improving knowledge base");

    if (notes.length === 0) notes.push("All evaluation metrics within acceptable ranges");

    return notes.join(". ");
  }

  // ─── Reports ──────────────────────────────────────────────────────────────

  generateReport(
    tenantId: number,
    startTimestamp: number,
    endTimestamp: number
  ): EvaluationReport {
    const periodEvals = this.evaluations.filter(
      (e) =>
        e.tenant_id === tenantId &&
        e.evaluated_at >= startTimestamp &&
        e.evaluated_at <= endTimestamp
    );

    const count = periodEvals.length;
    if (count === 0) {
      return {
        period: { start: startTimestamp, end: endTimestamp },
        tenant_id: tenantId,
        total_interactions: 0,
        averages: { citation_quality: 0, hallucination_score: 0, consistency_score: 0, accuracy_score: 0, retrieval_score: 0, overall_score: 0 },
        trends: { citation_quality_trend: "stable", hallucination_trend: "stable", overall_trend: "stable" },
        by_assistant: {},
        recommendations: ["No evaluation data available for the specified period."],
      };
    }

    const avg = (key: keyof EvaluationResult) =>
      periodEvals.reduce((s, e) => s + (e[key] as number), 0) / count;

    // Trend analysis: compare first half vs second half
    const mid = Math.floor(periodEvals.length / 2);
    const firstHalf = periodEvals.slice(0, mid);
    const secondHalf = periodEvals.slice(mid);

    const trend = (key: keyof EvaluationResult): "improving" | "stable" | "declining" => {
      if (firstHalf.length === 0 || secondHalf.length === 0) return "stable";
      const firstAvg = firstHalf.reduce((s, e) => s + (e[key] as number), 0) / firstHalf.length;
      const secondAvg = secondHalf.reduce((s, e) => s + (e[key] as number), 0) / secondHalf.length;
      const diff = secondAvg - firstAvg;
      if (Math.abs(diff) < 0.05) return "stable";
      // For hallucination, lower is better (inverted)
      if (key === "hallucination_score") return diff < 0 ? "improving" : "declining";
      return diff > 0 ? "improving" : "declining";
    };

    // Generate recommendations
    const recommendations: string[] = [];
    const avgCitation = avg("citation_quality");
    const avgHallucination = avg("hallucination_score");
    const avgRetrieval = avg("retrieval_score");

    if (avgCitation < 0.5) recommendations.push("Improve source citation practices — prompt the AI to explicitly reference retrieved documents");
    if (avgHallucination > 0.3) recommendations.push("High hallucination rate detected — consider lowering RAG confidence threshold or adding more knowledge base documents");
    if (avgRetrieval < 0.4) recommendations.push("Retrieval effectiveness is low — review Qdrant collection content and consider re-indexing with better metadata");
    if (recommendations.length === 0) recommendations.push("AI performance metrics are within acceptable ranges. Continue monitoring.");

    return {
      period: { start: startTimestamp, end: endTimestamp },
      tenant_id: tenantId,
      total_interactions: count,
      averages: {
        citation_quality: Math.round(avg("citation_quality") * 100) / 100,
        hallucination_score: Math.round(avg("hallucination_score") * 100) / 100,
        consistency_score: Math.round(avg("consistency_score") * 100) / 100,
        accuracy_score: Math.round(avg("accuracy_score") * 100) / 100,
        retrieval_score: Math.round(avg("retrieval_score") * 100) / 100,
        overall_score: Math.round(avg("overall_score") * 100) / 100,
      },
      trends: {
        citation_quality_trend: trend("citation_quality"),
        hallucination_trend: trend("hallucination_score"),
        overall_trend: trend("overall_score"),
      },
      by_assistant: {},
      recommendations,
    };
  }

  // ─── Query ────────────────────────────────────────────────────────────────

  getRecentEvaluations(tenantId: number, limit: number = 50): EvaluationResult[] {
    return this.evaluations
      .filter((e) => e.tenant_id === tenantId)
      .slice(-limit)
      .reverse();
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "ai_evaluation",
      total_evaluations: this.evaluations.length,
      weights: EVALUATION_WEIGHTS,
    };
  }
}

// Singleton instance
export const aiEvaluationService = new AIEvaluationService();
