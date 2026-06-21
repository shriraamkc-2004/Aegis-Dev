# Incident Report — INC-2024-002: Data Exfiltration Attempt

## Summary
On 2024-04-22 at 23:15 UTC, Aegis detected unusual outbound data transfers from an internal workstation to an external cloud storage endpoint.

## Detection Details
- **Anomaly ID**: #112
- **Detection Method**: ZSCORE+EWMA
- **Z-Score**: 5.23
- **iForest Score**: 0.691
- **Hybrid Score**: 0.687
- **Severity**: CRITICAL
- **Event Rate**: 2,340 outbound events/sec (baseline: 45 events/sec)
- **Source Entropy**: 0.08 (single workstation)

## Investigation
Workstation WS-4472 (user: jsmith) began uploading large volumes of data to an unauthorized cloud storage service at 23:15. The transfer continued for 12 minutes before detection triggered.

### Key Evidence
- 2.3 GB transferred to external IP in 12 minutes
- All transfers were HTTPS to a single destination (unauthorized SaaS)
- User jsmith had no business justification for the transfer
- Transfer occurred outside business hours

## Root Cause
Compromised user account (jsmith) used to exfiltrate sensitive project documents. Initial access was via a phishing email received 3 days prior.

## Resolution
- Workstation WS-4472 isolated from network (after analyst approval)
- User account suspended pending investigation
- Forensic image created of workstation
- Data loss assessment initiated
- Phishing email identified and removed from all mailboxes

## Lessons Learned
1. Outbound traffic monitoring was effective but detection took 12 minutes.
2. Off-hours activity should have lower detection thresholds.
3. Phishing awareness training was overdue for the affected department.
4. Network segmentation could have limited the data exposure.
