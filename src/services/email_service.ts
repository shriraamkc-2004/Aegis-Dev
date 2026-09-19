/**
 * Aegis SaaS — Transactional Email Service
 *
 * Sends emails for:
 *   - Email verification
 *   - Password reset
 *   - Welcome / org invite
 *   - Alert digests
 *
 * Provider:  Resend (primary) — set RESEND_API_KEY in .env
 * Fallback:  Logs the email to console (dev / no-key mode)
 *
 * All sends are non-blocking: the caller gets back immediately
 * and the email is dispatched asynchronously.
 */

// ─── Config ────────────────────────────────────────────────────────────────────

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const FROM_NAME = process.env.EMAIL_FROM_NAME || "Anomaly Aegis";
const FROM_ADDRESS = process.env.EMAIL_FROM_ADDRESS || "noreply@yourdomain.com";
const APP_URL = process.env.APP_URL || "http://localhost:3000";
const FROM = `${FROM_NAME} <${FROM_ADDRESS}>`;

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

interface SendResult {
  success: boolean;
  id?: string;
  error?: string;
}

// ─── Core Sender ────────────────────────────────────────────────────────────────

async function sendEmail(payload: EmailPayload): Promise<SendResult> {
  // Dev / no-key fallback: just log
  if (!RESEND_API_KEY) {
    console.log(`[EmailService] (no RESEND_API_KEY — logging only)`);
    console.log(`  TO:      ${payload.to}`);
    console.log(`  SUBJECT: ${payload.subject}`);
    console.log(`  BODY:    ${payload.text || "(html only)"}`);
    return { success: true, id: "dev-noop" };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: FROM,
        to: payload.to,
        subject: payload.subject,
        html: payload.html,
        text: payload.text,
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(
        `[EmailService] Resend API error ${response.status}: ${body}`,
      );
      return { success: false, error: `Resend API error: ${response.status}` };
    }

    const data = (await response.json()) as { id: string };
    return { success: true, id: data.id };
  } catch (err: any) {
    console.error("[EmailService] Network error sending email:", err.message);
    return { success: false, error: err.message };
  }
}

// ─── HTML Template Helper ──────────────────────────────────────────────────────

function wrapInTemplate(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; margin: 0; padding: 0; }
    .wrapper { max-width: 560px; margin: 40px auto; background: #1a1f2e; border-radius: 12px; overflow: hidden; border: 1px solid #2d3748; }
    .header { background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); padding: 32px 40px; }
    .header h1 { margin: 0; color: #fff; font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
    .header p { margin: 4px 0 0; color: rgba(255,255,255,0.8); font-size: 13px; }
    .body { padding: 32px 40px; }
    .body p { color: #cbd5e0; line-height: 1.7; margin: 0 0 16px; }
    .cta { display: inline-block; background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff !important; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 15px; margin: 8px 0 24px; }
    .code { background: #0f1117; border: 1px solid #2d3748; border-radius: 8px; padding: 16px 20px; font-family: monospace; font-size: 20px; letter-spacing: 4px; color: #a78bfa; text-align: center; margin: 16px 0; }
    .footer { padding: 20px 40px; border-top: 1px solid #2d3748; text-align: center; }
    .footer p { color: #4a5568; font-size: 12px; margin: 0; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <h1>🛡️ Anomaly Aegis</h1>
      <p>AI-Powered Security Operations Center</p>
    </div>
    <div class="body">
      ${body}
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} Anomaly Aegis. This is an automated message — please do not reply.</p>
    </div>
  </div>
</body>
</html>`;
}

// ─── Email Templates ───────────────────────────────────────────────────────────

/**
 * Send a welcome email to a newly registered organization admin.
 */
export async function sendWelcomeEmail(opts: {
  to: string;
  firstName: string;
  orgName: string;
}): Promise<SendResult> {
  const body = `
    <p>Hi ${opts.firstName},</p>
    <p>Welcome to <strong>Anomaly Aegis</strong>! Your organization <strong>${opts.orgName}</strong> has been created and your admin account is ready.</p>
    <p>You now have access to the full Aegis Security Operations Center — real-time anomaly detection, AI-powered threat analysis, and your Security Copilot.</p>
    <a class="cta" href="${APP_URL}/dashboard">Open Your Dashboard →</a>
    <p style="font-size:13px;color:#718096;">If you didn't sign up for Aegis, you can safely ignore this email.</p>
  `;
  return sendEmail({
    to: opts.to,
    subject: `Welcome to Anomaly Aegis, ${opts.firstName}!`,
    html: wrapInTemplate("Welcome to Anomaly Aegis", body),
    text: `Welcome to Anomaly Aegis! Your organization ${opts.orgName} is ready. Login at ${APP_URL}`,
  });
}

/**
 * Send an email verification link.
 */
export async function sendEmailVerification(opts: {
  to: string;
  firstName: string;
  token: string;
}): Promise<SendResult> {
  const link = `${APP_URL}/verify-email?token=${opts.token}`;
  const body = `
    <p>Hi ${opts.firstName},</p>
    <p>Please verify your email address to activate your Aegis account.</p>
    <a class="cta" href="${link}">Verify Email Address →</a>
    <p style="font-size:13px;color:#718096;">This link expires in 24 hours. If you didn't create an account, please ignore this email.</p>
  `;
  return sendEmail({
    to: opts.to,
    subject: "Verify your Aegis email address",
    html: wrapInTemplate("Email Verification", body),
    text: `Verify your email: ${link}`,
  });
}

/**
 * Send a password reset link.
 */
export async function sendPasswordResetEmail(opts: {
  to: string;
  firstName: string;
  token: string;
}): Promise<SendResult> {
  const link = `${APP_URL}/reset-password?token=${opts.token}`;
  const body = `
    <p>Hi ${opts.firstName},</p>
    <p>We received a request to reset your Aegis password. Click the button below to choose a new password.</p>
    <a class="cta" href="${link}">Reset My Password →</a>
    <p style="font-size:13px;color:#718096;">This link expires in 1 hour. If you didn't request a password reset, your account is safe — please ignore this email.</p>
  `;
  return sendEmail({
    to: opts.to,
    subject: "Reset your Aegis password",
    html: wrapInTemplate("Password Reset", body),
    text: `Reset your password: ${link}`,
  });
}

/**
 * Send an org invite email to a new team member.
 */
export async function sendOrgInviteEmail(opts: {
  to: string;
  inviteeName: string;
  inviterName: string;
  orgName: string;
  role: string;
  token: string;
}): Promise<SendResult> {
  const link = `${APP_URL}/accept-invite?token=${opts.token}`;
  const body = `
    <p>Hi ${opts.inviteeName},</p>
    <p><strong>${opts.inviterName}</strong> has invited you to join <strong>${opts.orgName}</strong> on Anomaly Aegis as a <strong>${opts.role}</strong>.</p>
    <p>Aegis is an AI-powered Security Operations Center — you'll have access to real-time threat detection, incident management, and an AI-powered Security Copilot.</p>
    <a class="cta" href="${link}">Accept Invitation →</a>
    <p style="font-size:13px;color:#718096;">This invitation expires in 7 days. If you weren't expecting this invite, please ignore it.</p>
  `;
  return sendEmail({
    to: opts.to,
    subject: `You've been invited to ${opts.orgName} on Anomaly Aegis`,
    html: wrapInTemplate("You're Invited!", body),
    text: `Accept your invitation to ${opts.orgName}: ${link}`,
  });
}

/**
 * Send a critical alert notification email.
 */
export async function sendAlertEmail(opts: {
  to: string;
  orgName: string;
  severity: string;
  title: string;
  diagnosis: string;
  incidentId: string | number;
}): Promise<SendResult> {
  const link = `${APP_URL}/dashboard/incidents/${opts.incidentId}`;
  const severityColor =
    opts.severity === "CRITICAL"
      ? "#ef4444"
      : opts.severity === "HIGH"
        ? "#f97316"
        : "#eab308";
  const body = `
    <p>A <strong style="color:${severityColor}">${opts.severity}</strong> security incident has been detected in <strong>${opts.orgName}</strong>.</p>
    <p><strong>${opts.title}</strong></p>
    <p style="color:#94a3b8;font-size:14px;">${opts.diagnosis}</p>
    <a class="cta" href="${link}">View Incident →</a>
  `;
  return sendEmail({
    to: opts.to,
    subject: `[${opts.severity}] Aegis Alert: ${opts.title}`,
    html: wrapInTemplate(`${opts.severity} Alert`, body),
    text: `${opts.severity} alert: ${opts.title}. View incident: ${link}`,
  });
}
