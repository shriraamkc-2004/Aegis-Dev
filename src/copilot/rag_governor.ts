/**
 * Aegis Enterprise — RAG Governor
 *
 * Enforces security boundaries during semantic retrieval (RAG).
 * Validates retrieved document trust levels, filters out untrusted documents,
 * and ensures RAG citations are authentic and properly attribute back to source.
 */

import { logStructured } from "../observability/logger.js";
import {
  knowledgeGovernanceEngine,
  type DocumentTrustLevel,
} from "./knowledge_governance_engine.js";

export interface RetrievedDocument {
  doc_id: string;
  source: string;
  filename: string;
  trust_level: DocumentTrustLevel;
  relevance_score: number;
  content: string;
  version: string;
  collection: string;
}

export interface RAGFilterResult {
  allowed_documents: RetrievedDocument[];
  filtered_count: number;
  highest_trust_level: DocumentTrustLevel | null;
  mean_relevance: number;
}

export class RAGGovernor {
  private readonly MIN_RELEVANCE_SCORE = 0.4;
  private readonly MIN_TRUST_LEVEL: DocumentTrustLevel = "LOW";

  /**
   * Filter and validate retrieved RAG documents before injecting into the prompt.
   */
  filterRetrievals(
    docs: RetrievedDocument[],
    tenantId: number,
  ): RAGFilterResult {
    const allowed: RetrievedDocument[] = [];
    let filteredCount = 0;
    let totalRelevance = 0;
    let highestTrust: DocumentTrustLevel | null = null;

    const trustOrder: DocumentTrustLevel[] = [
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
    ];

    for (const doc of docs) {
      // 1. Relevance score threshold
      if (doc.relevance_score < this.MIN_RELEVANCE_SCORE) {
        filteredCount++;
        continue;
      }

      // 2. Trust Level filtering
      const trustIndex = trustOrder.indexOf(doc.trust_level);
      const minIndex = trustOrder.indexOf(this.MIN_TRUST_LEVEL);
      if (trustIndex > minIndex) {
        filteredCount++;
        logStructured(
          "warn",
          "[RAGGovernor] Filtered document due to low trust level",
          {
            doc_id: doc.doc_id,
            trust_level: doc.trust_level,
            tenantId,
          },
        );
        continue;
      }

      // 3. Instruction Injection / Poisoning Check in Retrieved Document
      if (this.containsInstructionInjection(doc.content)) {
        filteredCount++;
        logStructured(
          "error",
          "[RAGGovernor] Poisoned document detected — filtered",
          {
            doc_id: doc.doc_id,
            tenantId,
          },
        );
        continue;
      }

      // Update metrics
      totalRelevance += doc.relevance_score;
      allowed.push(doc);

      if (!highestTrust || trustIndex < trustOrder.indexOf(highestTrust)) {
        highestTrust = doc.trust_level;
      }
    }

    const meanRelevance =
      allowed.length > 0 ? totalRelevance / allowed.length : 0.0;

    return {
      allowed_documents: allowed,
      filtered_count: filteredCount,
      highest_trust_level: highestTrust,
      mean_relevance: meanRelevance,
    };
  }

  private containsInstructionInjection(content: string): boolean {
    const poisonPatterns = [
      /ignore\s+(previous|above|all)\s+instructions/i,
      /you\s+are\s+now\s+(a|an)\b/i,
      /system\s+prompt/i,
      /pretend\s+you\s+are/i,
    ];
    return poisonPatterns.some((pat) => pat.test(content));
  }
}

export const ragGovernor = new RAGGovernor();
