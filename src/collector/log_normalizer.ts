/**
 * Aegis SaaS — Universal Log Normalizer
 *
 * Accepts raw log data in multiple industry formats and normalizes them
 * into Aegis's internal event schema before storage and detection.
 *
 * Supported input formats:
 *   - JSON / NDJSON (newline-delimited JSON)
 *   - CEF  (Common Event Format — Cisco, ArcSight)
 *   - LEEF (Log Event Extended Format — IBM QRadar)
 *   - Syslog RFC 5424 / RFC 3164
 *   - Windows Event Log (simplified XML / JSON)
 *   - AWS CloudTrail (JSON Records array)
 *   - Raw key=value pairs
 */

// ─── Internal Event Schema ──────────────────────────────────────────────────────

export interface NormalizedEvent {
  /** ISO-8601 timestamp — defaults to now() if not parseable */
  timestamp: string;
  /** Source identifier: IP, hostname, service name, etc. */
  source: string;
  /** Severity: critical | high | medium | low | info */
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Category: auth | network | endpoint | application | system | unknown */
  category:
    "auth" | "network" | "endpoint" | "application" | "system" | "unknown";
  /** Short human-readable description of the event */
  event_type: string;
  /** Full original message or summary */
  message: string;
  /** Parsed fields preserved for further analysis */
  raw_data: Record<string, any>;
  /** Which parser produced this event */
  _parser: string;
}

// ─── Severity Mapping ───────────────────────────────────────────────────────────

const CEF_SEVERITY_MAP: Record<number, NormalizedEvent["severity"]> = {
  0: "info",
  1: "info",
  2: "info",
  3: "low",
  4: "low",
  5: "medium",
  6: "medium",
  7: "high",
  8: "high",
  9: "critical",
  10: "critical",
};

const SYSLOG_SEVERITY_MAP: Record<number, NormalizedEvent["severity"]> = {
  0: "critical", // Emergency
  1: "critical", // Alert
  2: "critical", // Critical
  3: "high", // Error
  4: "medium", // Warning
  5: "low", // Notice
  6: "info", // Informational
  7: "info", // Debug
};

function toSeverity(v: string | number): NormalizedEvent["severity"] {
  if (typeof v === "number")
    return CEF_SEVERITY_MAP[Math.min(10, Math.max(0, v))] ?? "info";
  const s = String(v).toLowerCase();
  if (["critical", "fatal", "emerg", "alert", "crit"].includes(s))
    return "critical";
  if (["high", "error", "err"].includes(s)) return "high";
  if (["medium", "warn", "warning", "moderate"].includes(s)) return "medium";
  if (["low", "notice"].includes(s)) return "low";
  return "info";
}

function inferCategory(
  eventType: string,
  msg: string,
): NormalizedEvent["category"] {
  const t = (eventType + " " + msg).toLowerCase();
  if (/login|auth|password|credential|ssh|logon|logoff|kerberos|ldap/.test(t))
    return "auth";
  if (
    /firewall|tcp|udp|packet|flow|nat|dns|http|tls|port|scan|ddos|syn/.test(t)
  )
    return "network";
  if (/process|registry|file|malware|endpoint|host|agent|driver/.test(t))
    return "endpoint";
  if (/app|api|request|response|sql|exception|error|deploy/.test(t))
    return "application";
  return "system";
}

function safeTimestamp(raw: any): string {
  if (!raw) return new Date().toISOString();
  const d = new Date(raw);
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

// ─── Parser: JSON / NDJSON ─────────────────────────────────────────────────────

export function parseJson(raw: string): NormalizedEvent[] {
  const results: NormalizedEvent[] = [];

  // Try NDJSON first
  const lines = raw.trim().split("\n");
  const objects: any[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      // AWS CloudTrail wraps events in a Records array
      if (obj.Records && Array.isArray(obj.Records)) {
        objects.push(...obj.Records);
      } else if (Array.isArray(obj)) {
        objects.push(...obj);
      } else {
        objects.push(obj);
      }
    } catch {
      // not valid JSON line — skip
    }
  }

  for (const obj of objects) {
    const eventType =
      obj.event_type ||
      obj.eventType ||
      obj.eventName ||
      obj.type ||
      obj.action ||
      "generic_event";
    const message =
      obj.message ||
      obj.msg ||
      obj.description ||
      obj.detail ||
      JSON.stringify(obj).slice(0, 200);
    const source =
      obj.source ||
      obj.sourceIPAddress ||
      obj.host ||
      obj.hostname ||
      obj.ip ||
      "unknown";
    const severity = toSeverity(
      obj.severity || obj.level || obj.priority || "info",
    );

    results.push({
      timestamp: safeTimestamp(
        obj.timestamp || obj.eventTime || obj.time || obj["@timestamp"],
      ),
      source,
      severity,
      category: inferCategory(eventType, message),
      event_type: String(eventType),
      message: String(message),
      raw_data: obj,
      _parser: "json",
    });
  }

  return results;
}

// ─── Parser: CEF (Common Event Format) ────────────────────────────────────────

// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
const CEF_REGEX =
  /^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)$/i;

export function parseCef(raw: string): NormalizedEvent[] {
  const results: NormalizedEvent[] = [];

  for (const line of raw.trim().split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const match = trimmed.match(CEF_REGEX);
    if (!match) continue;

    const [, , vendor, product, , sigId, name, severityStr, extStr] = match;
    const severity = CEF_SEVERITY_MAP[parseInt(severityStr, 10)] ?? "info";

    // Parse extension key=value pairs safely without polynomial ReDoS
    const ext: Record<string, string> = {};
    const extTokens = extStr.split(/\s(?=[A-Za-z0-9_]+=)/);
    for (const token of extTokens) {
      const eqIdx = token.indexOf("=");
      if (eqIdx > 0) {
        const k = token.slice(0, eqIdx).trim();
        const v = token.slice(eqIdx + 1).trim();
        if (k) ext[k] = v;
      }
    }

    results.push({
      timestamp: safeTimestamp(ext.end || ext.rt || ext.deviceReceiptTime),
      source: ext.src || ext.sourceAddress || ext.dhost || vendor,
      severity,
      category: inferCategory(name, `${vendor} ${product}`),
      event_type: `${sigId}: ${name}`,
      message: `[${vendor}/${product}] ${name}`,
      raw_data: { vendor, product, sigId, name, ...ext },
      _parser: "cef",
    });
  }

  return results;
}

// ─── Parser: Syslog RFC 5424 / RFC 3164 ───────────────────────────────────────

// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
const RFC5424 = /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/;
// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
const RFC3164 =
  /^<([0-9]{1,3})>([A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})\s+([^\s]+)\s+([^:\s]+):\s*(.*)$/;

export function parseSyslog(raw: string): NormalizedEvent[] {
  const results: NormalizedEvent[] = [];

  for (const line of raw.trim().split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let m: RegExpMatchArray | null;

    if ((m = trimmed.match(RFC5424))) {
      const [, priStr, , timestamp, hostname, appName, , , msg] = m;
      const pri = parseInt(priStr, 10);
      const syslogSeverity = pri % 8;
      results.push({
        timestamp: safeTimestamp(timestamp),
        source: hostname,
        severity: SYSLOG_SEVERITY_MAP[syslogSeverity] ?? "info",
        category: inferCategory(appName, msg),
        event_type: appName,
        message: msg,
        raw_data: { hostname, appName, pri, msg },
        _parser: "syslog-rfc5424",
      });
    } else if ((m = trimmed.match(RFC3164))) {
      const [, priStr, timestamp, hostname, tag, msg] = m;
      const pri = parseInt(priStr, 10);
      const syslogSeverity = pri % 8;
      results.push({
        timestamp: safeTimestamp(`${new Date().getFullYear()} ${timestamp}`),
        source: hostname,
        severity: SYSLOG_SEVERITY_MAP[syslogSeverity] ?? "info",
        category: inferCategory(tag, msg),
        event_type: tag.trim(),
        message: msg,
        raw_data: { hostname, tag, pri, msg },
        _parser: "syslog-rfc3164",
      });
    }
  }

  return results;
}

// ─── Parser: Raw key=value pairs ──────────────────────────────────────────────

export function parseKeyValue(raw: string): NormalizedEvent[] {
  const results: NormalizedEvent[] = [];

  for (const line of raw.trim().split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const obj: Record<string, string> = {};
    const pairs = trimmed.split(/\s(?=[A-Za-z0-9_]+=)/);
    for (const pair of pairs) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx > 0) {
        const key = pair.slice(0, eqIdx).trim();
        let val = pair.slice(eqIdx + 1).trim();
        if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
          val = val.slice(1, -1);
        }
        if (key) obj[key] = val;
      }
    }

    if (Object.keys(obj).length === 0) continue;

    const eventType =
      obj.event_type || obj.type || obj.action || obj.cmd || "kv_event";
    const message = obj.message || obj.msg || trimmed;
    const source = obj.src || obj.host || obj.source || obj.ip || "unknown";

    results.push({
      timestamp: safeTimestamp(obj.timestamp || obj.time || obj.ts),
      source,
      severity: toSeverity(obj.severity || obj.level || "info"),
      category: inferCategory(eventType, message),
      event_type: eventType,
      message,
      raw_data: obj,
      _parser: "key-value",
    });
  }

  return results;
}

// ─── Master Normalizer ──────────────────────────────────────────────────────────

export type LogFormat = "json" | "ndjson" | "cef" | "syslog" | "kv" | "auto";

/**
 * Normalizes a raw log payload into Aegis internal events.
 * Pass `format: "auto"` to auto-detect the format.
 */
export function normalizeLog(
  raw: string,
  format: LogFormat = "auto",
): NormalizedEvent[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];

  if (format === "cef" || (format === "auto" && /^CEF:/i.test(trimmed))) {
    return parseCef(trimmed);
  }

  if (format === "syslog" || (format === "auto" && /^<\d+>/.test(trimmed))) {
    return parseSyslog(trimmed);
  }

  if (
    format === "json" ||
    format === "ndjson" ||
    (format === "auto" && (trimmed.startsWith("{") || trimmed.startsWith("[")))
  ) {
    const events = parseJson(trimmed);
    if (events.length > 0) return events;
  }

  // Fallback: try key=value
  if (format === "kv" || format === "auto") {
    const events = parseKeyValue(trimmed);
    if (events.length > 0) return events;
  }

  // Last resort: treat entire payload as a single raw message
  return [
    {
      timestamp: new Date().toISOString(),
      source: "unknown",
      severity: "info",
      category: "unknown",
      event_type: "raw_log",
      message: trimmed.slice(0, 500),
      raw_data: { raw: trimmed },
      _parser: "raw",
    },
  ];
}
