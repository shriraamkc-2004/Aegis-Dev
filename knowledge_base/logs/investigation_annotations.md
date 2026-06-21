# Aegis — Investigation Log Annotations Guide

## Analyst Annotation Standards

When investigating anomalies and incidents, SOC analysts should add structured annotations to the investigation log for future reference and RAG indexing.

### Annotation Format
```
[TIMESTAMP] [ANALYST_ID] [ACTION] [DETAILS]
```

### Action Types
- `ACKNOWLEDGE` — Alert acknowledged by analyst
- `INVESTIGATE` — Investigation initiated
- `CORRELATE` — Related events or anomalies identified
- `ESCALATE` — Incident escalated to senior analyst or management
- `MITIGATE` — Mitigation action applied (with approval reference)
- `RESOLVE` — Incident resolved
- `FALSE_POSITIVE` — Alert determined to be a false positive
- `NOTE` — General investigation note

### Example Annotations
```
[2024-03-15 02:35:00] [analyst_jdoe] [ACKNOWLEDGE] Alert #47 acknowledged
[2024-03-15 02:35:30] [analyst_jdoe] [INVESTIGATE] Checking source IP reputation
[2024-03-15 02:36:00] [analyst_jdoe] [CORRELATE] Found 3 related auth failures in last hour
[2024-03-15 02:36:30] [analyst_jdoe] [ESCALATE] Escalated to team lead — confirmed brute force
[2024-03-15 02:37:00] [teamlead_smith] [MITIGATE] IP block applied — approval ref: APR-2024-089
[2024-03-15 02:40:00] [teamlead_smith] [RESOLVE] Attack ceased, monitoring continues
```

### Indexing Notes
- All annotations are indexed into the Qdrant `logs` collection for semantic search.
- Analysts can search past investigations for similar patterns.
- Annotations are linked to incident IDs for full-context retrieval.

### Log Intelligence Patterns
Common investigation patterns that the copilot can surface:
- Repeated source IPs across incidents → Coordinated campaign
- Similar timing patterns → Automated attack tooling
- Same affected systems → Persistent vulnerability
- Recurring false positives → Detection tuning needed
