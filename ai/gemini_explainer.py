# Sensitive field encryption protects secrets and credentials only.
# PII masking is applied during presentation and external exposure only.
# Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.

import os
import json
import requests

class GeminiExplainer:
    """
    Interfaces with Gemini 2.5 Flash to generate natural language explanations for anomalies.
    Provides robust, deterministic fallback text in case of key absence or connection errors.
    """
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")

    def generate_explanation(self, severity, hybrid_score, z_score, ewma_score, iforest_score, possible_threat, event_count, agent_context=""):
        if not self.api_key:
            print("[Gemini Explainer] GEMINI_API_KEY is missing. Using local fallback.")
            return self._get_local_fallback(possible_threat, severity, z_score, hybrid_score)

        prompt = f"""
        You are a cybersecurity expert analyzing a SOC anomaly incident.
        Analyze the following incident metadata and provide a structured natural language explanation.
        
        Incident Metadata:
        - Severity: {severity}
        - Hybrid Score: {hybrid_score}
        - Z-Score: {z_score}
        - EWMA Score: {ewma_score}
        - Isolation Forest Score: {iforest_score}
        - Possible Threat Classification: {possible_threat}
        - Supporting Event Count: {event_count} events/sec
        - Agent Context: {agent_context}

        Your output MUST be a JSON object containing exactly the following keys:
        1. "executive_summary": A high-level description of what occurred (e.g. "Unusual authentication activity was observed within the monitoring window.")
        2. "technical_explanation": A detailed explanation of why the metrics indicate this possible threat (e.g. "The behaviour may indicate possible brute force activity due to repeated authentication failures.")
        3. "business_impact": The business/operational risk (e.g. "If left uninvestigated, this activity could result in unauthorized access attempts.")
        4. "recommended_actions": A list of bullet point actions to mitigate the risk (e.g. ["Review authentication logs", "Lock affected accounts", "Investigate originating systems"])

        Guidelines:
        - Use probabilistic language only (e.g., "Possible", "Likely", "May indicate").
        - NEVER claim certainty or confirm an attack (do not use "Attack Confirmed" or "DDoS Detected").
        - Output ONLY valid JSON.
        """

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2
            }
        }

        try:
            r = requests.post(url, headers=headers, json=payload, timeout=8)
            if r.status_code == 200:
                res_json = r.json()
                content = res_json["candidates"][0]["content"]["parts"][0]["text"].strip()
                explanation_data = json.loads(content)
                return self._format_explanation(explanation_data)
            else:
                print(f"[Gemini Explainer] Gemini API returned status: {r.status_code}. Falling back.")
        except Exception as e:
            print(f"[Gemini Explainer] Error calling Gemini API: {e}. Falling back.")

        return self._get_local_fallback(possible_threat, severity, z_score, hybrid_score)

    def _format_explanation(self, data):
        exec_summary = data.get("executive_summary", "")
        tech_exp = data.get("technical_explanation", "")
        impact = data.get("business_impact", "")
        rec_actions = data.get("recommended_actions", [])
        
        recs_str = "\n".join([f"- {r}" for r in rec_actions])
        
        return f"""**Executive Summary:** {exec_summary}

**Technical Explanation:** {tech_exp}

**Business Impact:** {impact}

**Recommended Actions:**
{recs_str}"""

    def _get_local_fallback(self, possible_threat, severity, z_score, hybrid_score):
        recs = {
            "Possible Brute Force Activity": "Review authentication logs and lock affected accounts.",
            "Possible DDoS Activity": "Review network traffic and enable mitigation controls.",
            "Possible Data Exfiltration": "Review outbound traffic and investigate affected systems.",
            "Possible Insider Threat": "Audit privileged access and investigate user activity.",
            "Possible Service Failure": "Investigate infrastructure health and service availability."
        }
        rec = recs.get(possible_threat, "Review system logs and investigate anomalies.")
        
        return f"""**Executive Summary:** An advisory check indicates {possible_threat or "unusual traffic spikes"}.

**Technical Explanation:** An anomaly was registered with Z-Score of {z_score:.2f} and Hybrid Score of {hybrid_score:.3f}.

**Business Impact:** The incident may lead to service degradation or security issues if left unaddressed.

**Recommended Actions:**
- {rec}
- Monitor active connections and logs.
- Verify source traffic distribution."""
