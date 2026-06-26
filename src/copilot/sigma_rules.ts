/**
 * Aegis Enterprise — Sigma Rules Engine
 * Parses and evaluates standardized Sigma rules against security event streams.
 */

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status: "stable" | "test" | "experimental";
  author: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    [key: string]: any; // selections/filters
    condition: string;
  };
  level: "low" | "medium" | "high" | "critical";
  tags?: string[];
}

export class SigmaRulesEngine {
  private rules: Map<string, SigmaRule> = new Map();

  constructor() {
    this.loadDefaultRules();
  }

  private loadDefaultRules(): void {
    const defaultRules: SigmaRule[] = [
      {
        id: "sigma-01",
        title: "Brute Force Authentication Failure",
        description: "Detects multiple authentication failures from a single user account",
        status: "stable",
        author: "Aegis SOC Team",
        logsource: { service: "authentication" },
        detection: {
          selection: {
            status: "failed",
            event_type: "auth_attempt"
          },
          condition: "selection"
        },
        level: "high",
        tags: ["attack.credential_access", "attack.t1110"]
      },
      {
        id: "sigma-02",
        title: "Privileged Execution by Non-Admin",
        description: "Detects admin operations triggered by standard users",
        status: "stable",
        author: "Aegis SOC Team",
        logsource: { service: "application" },
        detection: {
          selection: {
            action: "privileged_action",
            is_admin: false
          },
          condition: "selection"
        },
        level: "critical",
        tags: ["attack.privilege_escalation", "attack.t1078"]
      }
    ];

    for (const rule of defaultRules) {
      this.rules.set(rule.id, rule);
    }
  }

  /**
   * Add a custom Sigma rule to the engine.
   */
  addRule(rule: SigmaRule): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Evaluates all registered rules against a given log/event object.
   * Returns a list of rules that matched the event.
   */
  evaluateEvent(event: Record<string, any>): SigmaRule[] {
    const matchedRules: SigmaRule[] = [];

    for (const rule of this.rules.values()) {
      if (this.matchRule(rule, event)) {
        matchedRules.push(rule);
      }
    }

    return matchedRules;
  }

  private matchRule(rule: SigmaRule, event: Record<string, any>): boolean {
    const detection = rule.detection;
    const condition = detection.condition;

    // Resolve selections/filters defined in rule
    const resolvedBlocks: Record<string, boolean> = {};

    for (const key of Object.keys(detection)) {
      if (key === "condition") continue;
      
      const criteria = detection[key];
      resolvedBlocks[key] = this.evaluateCriteria(criteria, event);
    }

    // Evaluate simple condition expression (e.g. "selection" or "selection and not filter")
    if (condition === "selection") {
      return !!resolvedBlocks["selection"];
    }

    if (condition.includes(" and not ")) {
      const [selectKey, filterKey] = condition.split(" and not ").map(s => s.trim());
      return !!resolvedBlocks[selectKey] && !resolvedBlocks[filterKey];
    }

    // Default fallback to checking if any of the blocks match
    return Object.values(resolvedBlocks).some(Boolean);
  }

  private evaluateCriteria(criteria: any, event: Record<string, any>): boolean {
    if (typeof criteria !== "object" || criteria === null) return false;

    // All key-value pairs in the criteria must match the event fields
    for (const [key, val] of Object.entries(criteria)) {
      const eventVal = event[key];
      if (eventVal === undefined) return false;

      // Handle arrays in rules (e.g., event_type: ["login", "auth"])
      if (Array.isArray(val)) {
        if (!val.map(v => String(v).toLowerCase()).includes(String(eventVal).toLowerCase())) {
          return false;
        }
      } else {
        if (String(eventVal).toLowerCase() !== String(val).toLowerCase()) {
          return false;
        }
      }
    }

    return true;
  }

  getRulesCount(): number {
    return this.rules.size;
  }
}

export const sigmaRulesEngine = new SigmaRulesEngine();
