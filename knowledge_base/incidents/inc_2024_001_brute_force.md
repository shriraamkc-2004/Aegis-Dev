# Incident Report — INC-2024-001: Brute Force Authentication Attack

## Summary
On 2024-03-15 at 02:34 UTC, the Aegis detection engine identified a brute force authentication attack targeting the corporate VPN gateway.

## Detection Details
- **Anomaly ID**: #47
- **Detection Method**: HYBRID (Z-score + iForest + EWMA)
- **Z-Score**: 4.87
- **iForest Score**: 0.782
- **Hybrid Score**: 0.723
- **Severity**: CRITICAL
- **Event Rate**: 847 events/sec (baseline: 12 events/sec)
- **Source Entropy**: 0.12 (single source IP)

## Investigation
The AI agent traced the attack to a single external IP (203.0.113.42) making rapid authentication attempts against the VPN gateway. The attack targeted 3 distinct user accounts with an average of 282 login attempts per account per minute.

### Timeline
- 02:34:00 — First anomalous auth_failure spike detected
- 02:34:15 — iForest confirms anomaly (score 0.782)
- 02:34:18 — Threat classifier: "Brute Force" (94% confidence)
- 02:34:20 — Discord alert sent to SOC channel
- 02:35:00 — Analyst acknowledges alert
- 02:36:00 — Temporary IP block applied (after analyst approval)
- 02:40:00 — Attack ceases

## Root Cause
Automated credential stuffing tool targeting VPN from external IP. The attacker used a dictionary of common passwords against known employee email addresses.

## Resolution
- IP 203.0.113.42 blocked at firewall
- Affected accounts forced password reset
- Account lockout policy tightened (5 attempts → 15 minute lockout)
- VPN MFA enforcement accelerated

## Lessons Learned
1. Pre-existing account lockout policy was too permissive (20 attempts).
2. MFA was not enforced on VPN for all users.
3. Detection latency was acceptable (18 seconds from first anomalous event).
4. iForest warmup period had completed, enabling hybrid detection.
