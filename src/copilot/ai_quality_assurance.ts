/**
 * Aegis Enterprise — AI Quality Assurance Engine
 *
 * Runs post-generation quality and compliance checks on LLM responses.
 * Verifies structural format, markdown compliance, required sections,
 * readability, professional tone, and length limits.
 */

import { logStructured } from "../observability/logger.js";

export interface QARequirement {
  id: string;
  name: string;
  type: "regex" | "custom";
  pattern?: RegExp;
  description: string;
  severity: "critical" | "warning";
}

export interface QACheckResult {
  passed: boolean;
  score: number; // 0.0 - 1.0
  violations: string[];
  warnings: string[];
  checksRun: number;
}

const DEFAULT_QA_REQUIREMENTS: QARequirement[] = [
  {
    id: "QA_REQ_001",
    name: "Executive Summary Header",
    type: "regex",
    pattern: /^## 🔍 Executive Summary/m,
    description: "Response must start with an Executive Summary section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_002",
    name: "Evidence Summary Header",
    type: "regex",
    pattern: /^## 📊 Evidence Summary/m,
    description: "Response must contain an Evidence Summary section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_003",
    name: "Threat Explanation Header",
    type: "regex",
    pattern: /^## 🧩 Threat Explanation/m,
    description: "Response must contain a Threat Explanation section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_004",
    name: "MITRE ATT&CK Mapping Header",
    type: "regex",
    pattern: /^## 🎯 MITRE ATT&CK Mapping/m,
    description: "Response must contain a MITRE ATT&CK Mapping section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_005",
    name: "Limitations Header",
    type: "regex",
    pattern: /^## ⚠️ Risk Assessment/m,
    description: "Response must contain a Risk Assessment section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_006",
    name: "Recommended Actions Header",
    type: "regex",
    pattern: /^## 🛡️ Recommended Actions/m,
    description: "Response must contain a Recommended Actions section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_007",
    name: "Limitations Section",
    type: "regex",
    pattern: /^## ⚡ Limitations/m,
    description: "Response must contain a Limitations section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_008",
    name: "Evidence Sources Header",
    type: "regex",
    pattern: /^## 📚 Evidence Sources/m,
    description: "Response must contain an Evidence Sources section.",
    severity: "critical",
  },
  {
    id: "QA_REQ_009",
    name: "Confidence Statement Header",
    type: "regex",
    pattern: /^## 📈 Confidence Statement/m,
    description: "Response must contain a Confidence Statement section.",
    severity: "critical",
  },
];

export class AIQualityAssuranceEngine {
  private requirements: QARequirement[] = [...DEFAULT_QA_REQUIREMENTS];

  /**
   * Run structural quality checks on the raw LLM response.
   */
  checkResponse(response: string): QACheckResult {
    const violations: string[] = [];
    const warnings: string[] = [];
    let passedChecks = 0;

    if (!response || response.trim().length === 0) {
      return {
        passed: false,
        score: 0.0,
        violations: ["Response is empty or null."],
        warnings: [],
        checksRun: this.requirements.length,
      };
    }

    // Check formatting / markdown requirements
    for (const req of this.requirements) {
      if (req.type === "regex" && req.pattern) {
        const matches = req.pattern.test(response);
        if (!matches) {
          const msg = `${req.name}: ${req.description}`;
          if (req.severity === "critical") {
            violations.push(msg);
          } else {
            warnings.push(msg);
          }
        } else {
          passedChecks++;
        }
      }
    }

    // Additional QA heuristic checks
    // 1. Length validation (e.g. too short to be descriptive, or exceeding safe bounds)
    if (response.length < 150) {
      warnings.push(
        "Response length is extremely short; response may lack depth.",
      );
    }

    // 2. Unprofessional or conversational language check
    const conversationalPatterns = [
      /\b(hey|hi|hello|dear analyst|hope you are doing well|my friend)\b/i,
      /\b(apologies for|sorry about|i am sorry)\b/i,
    ];
    for (const pat of conversationalPatterns) {
      if (pat.test(response)) {
        warnings.push(
          "Response contains overly conversational or informal text.",
        );
      }
    }

    const checksRun = this.requirements.length;
    const score = checksRun > 0 ? passedChecks / checksRun : 1.0;
    const passed = violations.length === 0;

    logStructured("info", "[AIQualityAssuranceEngine] QA check finished", {
      passed,
      score,
      violationsCount: violations.length,
      warningsCount: warnings.length,
    });

    return {
      passed,
      score,
      violations,
      warnings,
      checksRun,
    };
  }
}

export const aiQualityAssuranceEngine = new AIQualityAssuranceEngine();
