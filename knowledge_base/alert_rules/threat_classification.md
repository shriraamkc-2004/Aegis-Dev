# Aegis — Threat Classification Rules

## Threat Categories

### Brute Force Attack
- **Indicators**: High authentication failure rate from single source, rapid login attempts, multiple failed passwords for same account.
- **Severity**: HIGH
- **Detection**: Z-score spike in auth_failure events + source IP concentration.
- **Response**: Alert SOC analyst, recommend temporary IP block, enable account lockout policy.

### DDoS (Distributed Denial of Service)
- **Indicators**: Massive spike in inbound traffic volume, high source entropy (many unique IPs), service degradation.
- **Severity**: CRITICAL
- **Detection**: EWMA deviation + burst ratio > 0.8 + source entropy spike.
- **Response**: Activate rate limiting, notify infrastructure team, engage CDN mitigation.

### Data Exfiltration
- **Indicators**: Unusual outbound data volume, off-hours transfers, large file uploads to external destinations.
- **Severity**: CRITICAL
- **Detection**: Outbound traffic anomaly + high destination entropy + volume deviation.
- **Response**: Isolate affected endpoint (requires analyst approval), block external transfer, initiate forensics.

### Insider Threat
- **Indicators**: Privileged access at unusual times, bulk data access, policy violations, access to unrelated resources.
- **Severity**: HIGH
- **Detection**: Behavioral anomaly in user activity patterns + privilege escalation signals.
- **Response**: Flag for HR/security review, increase monitoring, do NOT auto-revoke (requires HITL approval).

### Service Failure
- **Indicators**: Sudden drop in event throughput, service health check failures, cascading timeout errors.
- **Severity**: MEDIUM to HIGH
- **Detection**: Negative Z-score (traffic drop) + error rate spike.
- **Response**: Check service health, review deployment logs, escalate to operations team.

## Severity Scoring Logic
Severity is calculated using a hybrid fusion score:
- **CRITICAL**: hybrid_score >= 0.7 OR z_score > 5.0
- **HIGH**: hybrid_score >= 0.5 OR z_score > 4.0
- **MEDIUM**: hybrid_score >= 0.3 OR z_score > 3.0
- **LOW**: Below all thresholds

## Discord Alert Rules
- CRITICAL and HIGH severity anomalies trigger Discord alerts.
- Alerts include: anomaly ID, severity, detection method, Z-score, hybrid score, and recommended action.
- Rate limiting: Maximum 1 alert per 30 seconds to prevent flooding.
