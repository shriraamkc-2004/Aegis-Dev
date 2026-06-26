/**
 * Aegis Enterprise — IOC Ingestion Service
 * Handles ingestion, validation, and searching of Indicators of Compromise (IOCs).
 * Supports fetching from public feeds and managing custom database lists.
 */

import { threatIntelService, ThreatIntelResult } from "./threat_intel.js";

export interface IOCRecord {
  value: string;
  type: "ip" | "domain" | "hash";
  source: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  first_seen: number;
  last_seen: number;
}

export class IOCIngestionService {
  private localStore: Map<string, IOCRecord> = new Map();

  constructor() {
    this.initDefaultFeeds();
  }

  private initDefaultFeeds(): void {
    // Populate some initial benchmark IOCs for SOC scenarios
    const sampleIocs: IOCRecord[] = [
      {
        value: "198.51.100.45",
        type: "ip",
        source: "abuseipdb_feed",
        severity: "HIGH",
        description: "Known Command and Control server IP address",
        first_seen: Date.now() - 86400000,
        last_seen: Date.now()
      },
      {
        value: "malicious-domain-download.xyz",
        type: "domain",
        source: "alienvault_otx",
        severity: "CRITICAL",
        description: "Host distributing phishing and credential stealing malware",
        first_seen: Date.now() - 172800000,
        last_seen: Date.now()
      },
      {
        value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        type: "hash",
        source: "custom_import",
        severity: "MEDIUM",
        description: "Known empty file hash indicator for test cases",
        first_seen: Date.now() - 3600000,
        last_seen: Date.now()
      }
    ];

    for (const ioc of sampleIocs) {
      this.localStore.set(`${ioc.type}:${ioc.value}`, ioc);
    }
  }

  /**
   * Ingest and save a batch of new IOC records.
   */
  async ingestIOCs(records: Omit<IOCRecord, "first_seen" | "last_seen">[]): Promise<number> {
    let count = 0;
    const now = Date.now();
    for (const r of records) {
      const key = `${r.type}:${r.value}`;
      const existing = this.localStore.get(key);
      const record: IOCRecord = {
        ...r,
        first_seen: existing ? existing.first_seen : now,
        last_seen: now
      };
      this.localStore.set(key, record);
      count++;
    }
    return count;
  }

  /**
   * Ingest from raw formats (CSV, TSV, or JSON lines).
   */
  async ingestFromRaw(rawData: string, format: "csv" | "json"): Promise<number> {
    const ingested: Omit<IOCRecord, "first_seen" | "last_seen">[] = [];
    
    if (format === "json") {
      const lines = rawData.split("\n").filter(l => l.trim() !== "");
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.value && parsed.type) {
            ingested.push({
              value: parsed.value,
              type: parsed.type,
              source: parsed.source || "raw_json_feed",
              severity: parsed.severity || "MEDIUM",
              description: parsed.description || "Ingested indicator"
            });
          }
        } catch {
          // Skip invalid lines
        }
      }
    } else if (format === "csv") {
      const lines = rawData.split("\n").filter(l => l.trim() !== "");
      for (const line of lines) {
        const parts = line.split(",").map(p => p.trim());
        if (parts.length >= 2) {
          const [value, type, source, severity, description] = parts;
          if (["ip", "domain", "hash"].includes(type)) {
            ingested.push({
              value,
              type: type as any,
              source: source || "raw_csv_feed",
              severity: (severity as any) || "MEDIUM",
              description: description || "Ingested indicator"
            });
          }
        }
      }
    }

    return this.ingestIOCs(ingested);
  }

  /**
   * Match an incoming value against both our ingested list and external threat intel.
   */
  async checkIndicator(type: "ip" | "domain" | "hash", value: string): Promise<ThreatIntelResult[]> {
    const key = `${type}:${value}`;
    const local = this.localStore.get(key);
    const results: ThreatIntelResult[] = [];

    if (local) {
      results.push({
        source: "custom",
        indicator_type: type,
        indicator_value: value,
        confidence: 1.0,
        severity: local.severity,
        metadata: {
          description: local.description,
          feed_source: local.source,
          last_seen: local.last_seen
        }
      });
    }

    // Call external lookup from ThreatIntelService
    const external = await threatIntelService.lookupIndicator(type, value);
    results.push(...external);

    return results;
  }

  getStatus() {
    return {
      service: "ioc_ingester",
      total_indicators: this.localStore.size,
      types: {
        ip: Array.from(this.localStore.values()).filter(i => i.type === "ip").length,
        domain: Array.from(this.localStore.values()).filter(i => i.type === "domain").length,
        hash: Array.from(this.localStore.values()).filter(i => i.type === "hash").length
      }
    };
  }
}

export const iocIngestionService = new IOCIngestionService();
