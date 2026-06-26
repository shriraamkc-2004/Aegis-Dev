/**
 * Aegis Enterprise — Webhook Notification Dispatcher
 * Extends notifications to Slack, Discord, and external SOAR webhook platforms.
 */

import { maskPii } from "../discord_alert.js";

export interface WebhookPayload {
  incident_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  description: string;
  mitigation?: string;
  timestamp: number;
}

export class WebhookDispatcherService {
  /**
   * Dispatches alerts to a Slack channel using incoming webhook integration.
   */
  async dispatchSlack(webhookUrl: string, payload: WebhookPayload): Promise<boolean> {
    try {
      const color = payload.severity === "CRITICAL" ? "#FF0000" : payload.severity === "HIGH" ? "#FF8C00" : "#FFD700";
      
      const slackPayload = {
        attachments: [
          {
            color: color,
            title: `🚨 Aegis SOC Alert: ${payload.title}`,
            text: maskPii(payload.description),
            fields: [
              { title: "Severity", value: payload.severity, short: true },
              { title: "Incident ID", value: payload.incident_id, short: true },
              { title: "Mitigation", value: payload.mitigation || "Investigating", short: false }
            ],
            footer: "Aegis Security Operations Center",
            ts: Math.floor(payload.timestamp / 1000)
          }
        ]
      };

      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(slackPayload)
      });

      return response.ok;
    } catch (err: any) {
      console.error(`[Slack Webhook Error] Failed to dispatch Slack alert: ${err.message}`);
      return false;
    }
  }

  /**
   * Dispatches alerts to a generic REST endpoint (SOAR hook).
   */
  async dispatchGenericWebhook(webhookUrl: string, payload: WebhookPayload): Promise<boolean> {
    try {
      const response = await fetch(webhookUrl, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-Aegis-Event": "incident"
        },
        body: JSON.stringify({
          ...payload,
          description: maskPii(payload.description),
          dispatched_at: Date.now()
        })
      });

      return response.ok;
    } catch (err: any) {
      console.error(`[SOAR Webhook Error] Failed to dispatch SOAR alert: ${err.message}`);
      return false;
    }
  }

  /**
   * Placeholder to dispatch alerts to email notifications.
   */
  async dispatchEmail(to: string, payload: WebhookPayload): Promise<boolean> {
    // Enterprise integration placeholder (AWS SES, SendGrid, SMTP)
    console.log(`[Email Alert] Dispatched alert to ${to}: ${payload.title}`);
    return true;
  }
}

export const webhookDispatcherService = new WebhookDispatcherService();
