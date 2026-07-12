/**
 * Aegis Enterprise — Threat Intelligence Service
 * MITRE ATT&CK mapping, technique/tactic references, and extensibility
 * for VirusTotal, AbuseIPDB, and AlienVault OTX integrations.
 */

// ─── MITRE ATT&CK Types ────────────────────────────────────────────────────────

export interface MitreTechnique {
  id: string; // e.g., T1110
  name: string; // e.g., Brute Force
  tactic: string; // e.g., credential-access
  description: string;
  mitigation: string;
  detection: string;
  subtechniques?: { id: string; name: string }[];
}

export interface MitreTactic {
  id: string; // e.g., TA0001
  name: string; // e.g., Initial Access
  description: string;
}

export interface ThreatIntelResult {
  source:
    "mitre_attack" | "virustotal" | "abuseipdb" | "alienvault_otx" | "custom";
  indicator_type: "ip" | "domain" | "hash" | "technique" | "tactic" | "cve";
  indicator_value: string;
  confidence: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  metadata: Record<string, unknown>;
  first_seen?: number;
  last_seen?: number;
}

// ─── MITRE ATT&CK Knowledge Base ────────────────────────────────────────────────

export const MITRE_TACTICS: MitreTactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    description: "The adversary is trying to get into your network.",
  },
  {
    id: "TA0002",
    name: "Execution",
    description: "The adversary is trying to run malicious code.",
  },
  {
    id: "TA0003",
    name: "Persistence",
    description: "The adversary is trying to maintain their foothold.",
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    description: "The adversary is trying to gain higher-level permissions.",
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    description: "The adversary is trying to avoid being detected.",
  },
  {
    id: "TA0006",
    name: "Credential Access",
    description:
      "The adversary is trying to steal account names and passwords.",
  },
  {
    id: "TA0007",
    name: "Discovery",
    description: "The adversary is trying to figure out your environment.",
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    description: "The adversary is trying to move through your environment.",
  },
  {
    id: "TA0009",
    name: "Collection",
    description: "The adversary is trying to gather data of interest.",
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    description: "The adversary is trying to steal data.",
  },
  {
    id: "TA0011",
    name: "Command and Control",
    description:
      "The adversary is trying to communicate with compromised systems.",
  },
  {
    id: "TA0040",
    name: "Impact",
    description:
      "The adversary is trying to manipulate, interrupt, or destroy systems and data.",
  },
];

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "credential-access",
    description:
      "Adversaries may use brute force techniques to gain access to accounts.",
    mitigation:
      "Implement account lockout policies, enforce strong passwords, enable MFA.",
    detection:
      "Monitor for multiple failed authentication attempts from single or distributed sources.",
    subtechniques: [
      { id: "T1110.001", name: "Password Guessing" },
      { id: "T1110.002", name: "Password Cracking" },
      { id: "T1110.003", name: "Password Spraying" },
      { id: "T1110.004", name: "Credential Stuffing" },
    ],
  },
  {
    id: "T1498",
    name: "Network Denial of Service",
    tactic: "impact",
    description:
      "Adversaries may perform network denial of service attacks to degrade or block availability.",
    mitigation:
      "Deploy DDoS mitigation services, implement rate limiting, use CDN filtering.",
    detection:
      "Monitor for traffic volume spikes, unusual source IP distribution, and protocol anomalies.",
    subtechniques: [
      { id: "T1498.001", name: "Direct Network Flood" },
      { id: "T1498.002", name: "Reflection Amplification" },
    ],
  },
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "exfiltration",
    description:
      "Adversaries may steal data by exfiltrating it over a command and control channel.",
    mitigation:
      "Monitor outbound data transfers, implement DLP, restrict egress traffic.",
    detection:
      "Detect large outbound transfers, unusual protocols, or connections to known-bad IPs.",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "persistence",
    description:
      "Adversaries may obtain and abuse credentials of existing accounts.",
    mitigation:
      "Enforce least privilege, rotate credentials, monitor for anomalous account usage.",
    detection:
      "Monitor logins from unusual locations, times, or devices. Track privilege escalation.",
    subtechniques: [
      { id: "T1078.001", name: "Default Accounts" },
      { id: "T1078.002", name: "Domain Accounts" },
      { id: "T1078.003", name: "Local Accounts" },
      { id: "T1078.004", name: "Cloud Accounts" },
    ],
  },
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "execution",
    description:
      "Adversaries may abuse command and script interpreters to execute commands.",
    mitigation:
      "Restrict script execution, use application whitelisting, monitor process creation.",
    detection:
      "Monitor process execution for unusual scripts, encoded commands, or suspicious parent-child relationships.",
  },
  {
    id: "T1566",
    name: "Phishing",
    tactic: "initial-access",
    description:
      "Adversaries may send phishing messages to gain access to victim systems.",
    mitigation:
      "Train users on phishing awareness, implement email filtering, use DMARC/SPF/DKIM.",
    detection:
      "Monitor email logs for suspicious senders, links, and attachments.",
    subtechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment" },
      { id: "T1566.002", name: "Spearphishing Link" },
      { id: "T1566.003", name: "Spearphishing via Service" },
    ],
  },
  {
    id: "T1021",
    name: "Remote Services",
    tactic: "lateral-movement",
    description:
      "Adversaries may use remote services to move laterally within a network.",
    mitigation:
      "Restrict remote access, implement network segmentation, monitor lateral connections.",
    detection:
      "Monitor for unusual remote desktop, SSH, or WinRM connections between internal hosts.",
  },
  {
    id: "T1055",
    name: "Process Injection",
    tactic: "defense-evasion",
    description:
      "Adversaries may inject code into processes to evade detection.",
    mitigation:
      "Use EDR solutions, enable ASLR, monitor for suspicious memory allocations.",
    detection:
      "Monitor for unusual process memory access patterns and DLL loading.",
  },
  {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: "command-and-control",
    description:
      "Adversaries may use application layer protocols for C2 communications.",
    mitigation:
      "Inspect encrypted traffic, block unauthorized protocols, monitor DNS queries.",
    detection:
      "Detect beaconing patterns, unusual DNS queries, or HTTP requests to suspicious domains.",
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tactic: "impact",
    description:
      "Adversaries may encrypt data on target systems to interrupt availability (ransomware).",
    mitigation:
      "Maintain offline backups, implement file integrity monitoring, restrict write access.",
    detection:
      "Monitor for mass file modifications, unusual encryption operations, or ransom notes.",
  },
];

// ─── Anomaly-to-MITRE Mapping ──────────────────────────────────────────────────

interface AnomalyMapping {
  patterns: string[];
  techniques: string[];
  tactics: string[];
  description: string;
}

const ANOMALY_TO_MITRE: AnomalyMapping[] = [
  {
    patterns: [
      "brute_force",
      "brute force",
      "failed_login",
      "authentication",
      "failed_login",
    ],
    techniques: ["T1110"],
    tactics: ["TA0006"],
    description: "Repeated authentication failures suggest brute force attack",
  },
  {
    patterns: ["ddos", "denial_of_service", "traffic_spike", "flood", "ddos"],
    techniques: ["T1498"],
    tactics: ["TA0040"],
    description: "Traffic volume spike suggests DDoS attack",
  },
  {
    patterns: ["exfiltration", "data_transfer", "outbound", "exfil"],
    techniques: ["T1041"],
    tactics: ["TA0010"],
    description: "Unusual outbound data transfers suggest data exfiltration",
  },
  {
    patterns: [
      "insider",
      "privileged",
      "insider_threat",
      "unauthorized_access",
    ],
    techniques: ["T1078"],
    tactics: ["TA0003"],
    description: "Privileged account abuse suggests insider threat",
  },
  {
    patterns: ["malware", "ransomware", "encrypted", "ransom"],
    techniques: ["T1486", "T1059"],
    tactics: ["TA0040", "TA0002"],
    description: "Potential malware or ransomware activity detected",
  },
  {
    patterns: ["lateral", "lateral_movement", "remote_service"],
    techniques: ["T1021"],
    tactics: ["TA0008"],
    description: "Lateral movement indicators detected",
  },
];

// ─── Threat Intelligence Service ────────────────────────────────────────────────

export class ThreatIntelService {
  private cache: Map<string, ThreatIntelResult> = new Map();

  // ─── MITRE ATT&CK Lookup ──────────────────────────────────────────────────

  getTechnique(techniqueId: string): MitreTechnique | null {
    return (
      MITRE_TECHNIQUES.find(
        (t) =>
          t.id === techniqueId ||
          t.subtechniques?.some((s) => s.id === techniqueId),
      ) || null
    );
  }

  getTactic(tacticId: string): MitreTactic | null {
    return MITRE_TACTICS.find((t) => t.id === tacticId) || null;
  }

  getAllTechniques(): MitreTechnique[] {
    return MITRE_TECHNIQUES;
  }

  getAllTactics(): MitreTactic[] {
    return MITRE_TACTICS;
  }

  getTechniquesByTactic(tacticName: string): MitreTechnique[] {
    const normalizedTactic = tacticName.toLowerCase().replace(/\s+/g, "-");
    return MITRE_TECHNIQUES.filter((t) => t.tactic === normalizedTactic);
  }

  // ─── Anomaly-to-MITRE Mapping ─────────────────────────────────────────────

  mapAnomalyToMitre(
    anomalyDescription: string,
    eventType?: string,
  ): {
    techniques: MitreTechnique[];
    tactics: MitreTactic[];
    mapping_description: string;
  } {
    const combined = (
      anomalyDescription +
      " " +
      (eventType || "")
    ).toLowerCase();
    const matchedTechniqueIds = new Set<string>();
    const matchedTacticIds = new Set<string>();
    const descriptions: string[] = [];

    for (const mapping of ANOMALY_TO_MITRE) {
      const matches = mapping.patterns.some((p) => combined.includes(p));
      if (matches) {
        mapping.techniques.forEach((t) => matchedTechniqueIds.add(t));
        mapping.tactics.forEach((t) => matchedTacticIds.add(t));
        descriptions.push(mapping.description);
      }
    }

    const techniques = Array.from(matchedTechniqueIds)
      .map((id) => this.getTechnique(id))
      .filter(Boolean) as MitreTechnique[];

    const tactics = Array.from(matchedTacticIds)
      .map((id) => this.getTactic(id))
      .filter(Boolean) as MitreTactic[];

    return {
      techniques,
      tactics,
      mapping_description:
        descriptions.join("; ") || "No specific MITRE ATT&CK mapping found",
    };
  }

  // ─── Threat Intel Lookup (extensible interface) ───────────────────────────

  async lookupIndicator(
    indicatorType: "ip" | "domain" | "hash",
    value: string,
  ): Promise<ThreatIntelResult[]> {
    const cacheKey = `${indicatorType}:${value}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return [cached];

    // Extensible: integrate with external providers
    // Currently returns cached or empty results
    // Future: call VirusTotal, AbuseIPDB, AlienVault OTX APIs
    const results = await this.queryExternalProviders(indicatorType, value);
    for (const r of results) {
      this.cache.set(`${r.indicator_type}:${r.indicator_value}`, r);
    }
    return results;
  }

  // ─── External Provider Interface (extensible, not tightly coupled) ────────

  private async queryExternalProviders(
    indicatorType: "ip" | "domain" | "hash",
    value: string,
  ): Promise<ThreatIntelResult[]> {
    // Placeholder for external provider integration
    // Each provider implements a standard interface:
    //   - VirusTotal: /api/v3/ip_addresses/{ip}, /api/v3/domains/{domain}
    //   - AbuseIPDB: /api/v2/check?ipAddress={ip}
    //   - AlienVault OTX: /api/v1/indicators/ipv4/{ip}/general
    //
    // Configuration via environment variables:
    //   VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ALIENVAULT_API_KEY

    const results: ThreatIntelResult[] = [];

    // If VIRUSTOTAL_API_KEY is configured, query VirusTotal
    if (process.env.VIRUSTOTAL_API_KEY) {
      try {
        const vtResult = await this.queryVirusTotal(indicatorType, value);
        if (vtResult) results.push(vtResult);
      } catch {
        // Provider unavailable — graceful degradation
      }
    }

    return results;
  }

  private async queryVirusTotal(
    indicatorType: string,
    value: string,
  ): Promise<ThreatIntelResult | null> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return null;

    // Strict input validation to prevent SSRF and parameter pollution
    const trimmed = value.trim();

    let url = "";
    if (indicatorType === "ip") {
      const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
      const isValid =
        (ipv4Regex.test(trimmed) &&
          trimmed
            .split(".")
            .map(Number)
            .every((p) => p >= 0 && p <= 255)) ||
        ipv6Regex.test(trimmed);
      if (!isValid) return null;

      // Prevent localhost or private IP addresses
      if (
        trimmed.startsWith("127.") ||
        trimmed.startsWith("10.") ||
        trimmed.startsWith("192.168.") ||
        trimmed.startsWith("172.16.") ||
        trimmed === "0.0.0.0"
      ) {
        return null;
      }
      url = `https://www.virustotal.com/api/v3/ip_addresses/${trimmed}`;
    } else if (indicatorType === "domain") {
      const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      const isValid =
        domainRegex.test(trimmed) &&
        !trimmed.toLowerCase().includes("localhost") &&
        !trimmed.toLowerCase().endsWith(".local") &&
        !trimmed.toLowerCase().endsWith(".internal");
      if (!isValid) return null;
      url = `https://www.virustotal.com/api/v3/domains/${trimmed}`;
    } else if (indicatorType === "hash") {
      const hashRegex = /^[a-fA-F0-9]{32,64}$/;
      const isValid =
        hashRegex.test(trimmed) && [32, 40, 64].includes(trimmed.length);
      if (!isValid) return null;
      url = `https://www.virustotal.com/api/v3/files/${trimmed}`;
    } else {
      return null;
    }

    const response = await fetch(url, {
      headers: { "x-apikey": apiKey },
    });

    if (!response.ok) return null;

    const data = (await response.json()) as any;
    const attrs = data?.data?.attributes;
    if (!attrs) return null;

    const malicious = attrs.last_analysis_stats?.malicious || 0;
    const total = Object.values(attrs.last_analysis_stats || {}).reduce(
      (a: number, b: any) => a + (b as number),
      0,
    ) as number;

    return {
      source: "virustotal",
      indicator_type: indicatorType as any,
      indicator_value: value,
      confidence: total > 0 ? malicious / total : 0,
      severity:
        malicious > 10
          ? "CRITICAL"
          : malicious > 3
            ? "HIGH"
            : malicious > 0
              ? "MEDIUM"
              : "LOW",
      metadata: {
        malicious_count: malicious,
        total_engines: total,
        country: attrs.country,
        reputation: attrs.reputation,
      },
    };
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "threat_intel",
      mitre_techniques: MITRE_TECHNIQUES.length,
      mitre_tactics: MITRE_TACTICS.length,
      anomaly_mappings: ANOMALY_TO_MITRE.length,
      cache_size: this.cache.size,
      providers: {
        virustotal: !!process.env.VIRUSTOTAL_API_KEY,
        abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
        alienvault: !!process.env.ALIENVAULT_API_KEY,
      },
    };
  }
}

// Singleton instance
export const threatIntelService = new ThreatIntelService();
