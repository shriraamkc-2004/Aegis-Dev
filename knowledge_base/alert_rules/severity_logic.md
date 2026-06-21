# Aegis — Severity Scoring & Alert Logic

## Hybrid Detection Pipeline

The hybrid detector combines three detection methods for robust anomaly scoring:

### 1. Z-Score Statistical Analysis
- Calculates rolling mean and standard deviation over a configurable window (default 60s).
- Z-score = (current_value - window_mean) / window_std
- Threshold: 3.0 standard deviations (configurable)

### 2. Isolation Forest (iForest)
- Unsupervised ML model that isolates anomalies in feature space.
- Features: event_count, z_score, source_entropy, burst_ratio
- Score range: 0.0 (normal) to 1.0 (highly anomalous)
- Requires warmup period (minimum 200 events) before producing reliable scores.

### 3. EWMA (Exponentially Weighted Moving Average)
- Tracks smoothed moving average with configurable alpha (default 0.15).
- Detects gradual drift and sustained deviations.
- Score: deviation of current value from EWMA baseline.

## Fusion Scoring
When hybrid fusion is enabled, the three scores are combined:
```
hybrid_score = w1 * normalized_zscore + w2 * iforest_score + w3 * abs(ewma_score)
```
Default weights are auto-calibrated based on detection confidence.

## Detection Method Labels
- `ZSCORE` — Only Z-score triggered (no iForest warmup complete)
- `ZSCORE+EWMA` — Z-score and EWMA agree
- `HYBRID` — All three methods fused

## Alert Escalation
1. Anomaly detected → Auto-creates incident record
2. AI agent investigates → Generates diagnosis and recommendation
3. Gemini summarizes → Human-readable explanation added to incident
4. Discord alert fires → SOC team notified (CRITICAL/HIGH only)
5. Analyst acknowledges → Status moves from OPEN to INVESTIGATING
