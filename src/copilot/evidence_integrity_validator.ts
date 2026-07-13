/**
 * Aegis Enterprise — Evidence Integrity Validator
 *
 * Generates and verifies SHA-256 integrity hashes for EvidenceBundle objects.
 * Ensures evidence has not been tampered between assembly and AI invocation.
 * Every evidence bundle is hashed at assembly time and re-verified before LLM call.
 */

import { createHash } from "crypto";
import { logStructured } from "../observability/logger.js";
import type { EvidenceBundle } from "./evidence_validator.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface IntegrityStamp {
  hash: string; // SHA-256 hex digest of the canonical evidence JSON
  stamped_at: number; // Unix timestamp (ms) when stamp was generated
  anomaly_id: number;
  tenant_id: number;
}

export interface IntegrityVerificationResult {
  valid: boolean;
  hash_matched: boolean;
  age_ms: number;
  stale: boolean; // True if evidence is > 30 minutes old
  rejection_reason: string | null;
}

// Evidence staleness threshold (30 minutes)
const EVIDENCE_STALENESS_MS = 30 * 60 * 1000;

// ─── Evidence Integrity Validator ────────────────────────────────────────────

export class EvidenceIntegrityValidator {
  /**
   * Generate an integrity stamp for an EvidenceBundle.
   * Call this immediately after assembling the bundle from deterministic engines.
   */
  stamp(bundle: EvidenceBundle): IntegrityStamp {
    const canonical = this.canonicalize(bundle);
    const hash = createHash("sha256").update(canonical).digest("hex");
    const stamp: IntegrityStamp = {
      hash,
      stamped_at: Date.now(),
      anomaly_id: bundle.anomaly_id,
      tenant_id: bundle.tenant_id,
    };
    logStructured("info", "[EvidenceIntegrity] Bundle stamped", {
      anomaly_id: bundle.anomaly_id,
      tenant_id: bundle.tenant_id,
      hash: hash.slice(0, 12) + "…",
    });
    return stamp;
  }

  /**
   * Verify an EvidenceBundle against its stamp.
   * Returns a detailed result including tamper detection and staleness.
   */
  verify(
    bundle: EvidenceBundle,
    stamp: IntegrityStamp,
  ): IntegrityVerificationResult {
    const canonical = this.canonicalize(bundle);
    const currentHash = createHash("sha256").update(canonical).digest("hex");
    const hashMatched = currentHash === stamp.hash;
    const ageMs = Date.now() - stamp.stamped_at;
    const stale = ageMs > EVIDENCE_STALENESS_MS;

    let rejectionReason: string | null = null;

    if (
      bundle.anomaly_id !== stamp.anomaly_id ||
      bundle.tenant_id !== stamp.tenant_id
    ) {
      rejectionReason =
        "Evidence bundle identity mismatch: anomaly_id or tenant_id changed.";
    } else if (!hashMatched) {
      rejectionReason =
        "Evidence bundle integrity violation: SHA-256 hash mismatch. Possible tampering detected.";
      logStructured(
        "error",
        "[EvidenceIntegrity] TAMPER DETECTED — hash mismatch",
        {
          anomaly_id: bundle.anomaly_id,
          tenant_id: bundle.tenant_id,
          expected_hash: stamp.hash.slice(0, 12) + "…",
          actual_hash: currentHash.slice(0, 12) + "…",
        },
      );
    } else if (stale) {
      rejectionReason = `Evidence bundle is stale (${Math.round(ageMs / 60000)} minutes old, max 30 minutes).`;
      logStructured("warn", "[EvidenceIntegrity] Stale evidence bundle", {
        anomaly_id: bundle.anomaly_id,
        age_minutes: Math.round(ageMs / 60000),
      });
    }

    return {
      valid: hashMatched && !stale && rejectionReason === null,
      hash_matched: hashMatched,
      age_ms: ageMs,
      stale,
      rejection_reason: rejectionReason,
    };
  }

  /**
   * Return the current hash of a bundle without a stamp (for audit records).
   */
  computeHash(bundle: EvidenceBundle): string {
    return createHash("sha256").update(this.canonicalize(bundle)).digest("hex");
  }

  // ── Private ───────────────────────────────────────────────────────────────

  /**
   * Produce a stable, deterministic JSON representation of the bundle.
   * Keys are sorted to ensure identical objects produce identical hashes.
   */
  private canonicalize(bundle: EvidenceBundle): string {
    return JSON.stringify(bundle, Object.keys(bundle).sort());
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const evidenceIntegrityValidator = new EvidenceIntegrityValidator();
