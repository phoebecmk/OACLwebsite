/**
 * api/submit-enquiry.js
 * Vercel Serverless Function — POST /api/submit-enquiry
 *
 * Pipeline on each submission:
 *   1. Method guard + CORS
 *   2. Rate limiting per IP
 *   3. Required-field validation
 *   4. reCAPTCHA v3 server-side verification
 *   5. Input sanitisation
 *   6. Send notification email to business (Resend)
 *   7. Send auto-reply to client (Resend)
 *   8. Create task in Zoho Projects (non-blocking — email still sends if this fails)
 *   9. Return success
 *
 * Required environment variables (set in Vercel dashboard):
 *   RECAPTCHA_SECRET_KEY   — https://google.com/recaptcha/admin
 *   RESEND_API_KEY         — https://resend.com/api-keys
 *   BUSINESS_EMAIL         — e.g. info@ocean-apex.com
 *   FROM_EMAIL             — verified Resend sender, e.g. enquiries@ocean-apex.com
 *   ALLOWED_ORIGIN         — e.g. https://www.ocean-apex.com
 *
 * Optional — Zoho Projects integration (task is skipped if not set):
 *   ZOHO_CLIENT_ID         — from Zoho API Console
 *   ZOHO_CLIENT_SECRET     — from Zoho API Console
 *   ZOHO_REFRESH_TOKEN     — long-lived token (see DEPLOY.md for setup)
 *   ZOHO_PORTAL_ID         — numeric portal ID from your Zoho Projects URL
 *   ZOHO_PROJECT_ID        — numeric project ID from your Zoho Projects URL
 *   ZOHO_DATA_CENTER       — com | eu | com.au | in | jp  (default: com)
 *   ZOHO_ASSIGNEE_EMAIL    — optional: auto-assign tasks to this team member
 */

import { Resend } from 'resend';

// ── Constants ─────────────────────────────────────────────────────────────────
const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
const RECAPTCHA_ACTION     = 'submit_enquiry';
const SCORE_THRESHOLD      = 0.5;

const SERVICE_LABELS = {
  incorporation: 'New Company Incorporation (HK, BVI, Cayman, Singapore & other jurisdictions)',
  secretary:     'Annual Company Secretary Retainer',
  nar1:          'Annual Return (NAR1) Filing',
  address:       'Registered Office Address',
  changes:       'Corporate Changes (Director / Shareholder / SCR filings)',
  scr:           'Significant Controllers Register Setup',
  banking:       'Bank Account Assistance',
};

const PAYMENT_LABELS = {
  card: 'Credit / Debit Card (Stripe)',
  bank: 'Bank Transfer / Wire',
};

// ── Rate limiter (in-memory; resets on cold start — best-effort only) ─────────
const rateLimitStore = new Map();
const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 10 * 60 * 1000;

function isRateLimited(ip) {
  const now  = Date.now();
  const data = rateLimitStore.get(ip) || { count: 0, windowStart: now };
  if (now - data.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return false;
  }
  if (data.count >= RATE_LIMIT_MAX) return true;
  data.count++;
  rateLimitStore.set(ip, data);
  return false;
}

// ── Input sanitisation ────────────────────────────────────────────────────────
function sanitize(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/<[^>]*>/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim()
    .slice(0, maxLen);
}

function sanitizeEmail(value) {
  return sanitize(value, 254).replace(/[\r\n]/g, '');
}

// ── Zoho Projects — create a task ─────────────────────────────────────────────
async function createZohoTask(enquiryData) {
  const dc             = process.env.ZOHO_DATA_CENTER || 'com';
  const clientId       = process.env.ZOHO_CLIENT_ID;
  const clientSecret   = process.env.ZOHO_CLIENT_SECRET;
  const refreshToken   = process.env.ZOHO_REFRESH_TOKEN;
  const portalId       = process.env.ZOHO_PORTAL_ID;
  const projectId      = process.env.ZOHO_PROJECT_ID;
  const assigneeEmail  = process.env.ZOHO_ASSIGNEE_EMAIL || '';

  // Step A — exchange the long-lived refresh token for a short-lived access token.
  // Zoho access tokens expire after 1 hour; the refresh token is permanent.
  const tokenRes = await fetch(
    `https://accounts.zoho.${dc}/oauth/v2/token` +
    `?grant_type=refresh_token` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&client_secret=${encodeURIComponent(clientSecret)}` +
    `&refresh_token=${encodeURIComponent(refreshToken)}`,
    { method: 'POST' }
  );
  const tokenData = await tokenRes.json();

  if (!tokenData.access_token) {
    throw new Error(`Zoho token refresh failed: ${JSON.stringify(tokenData)}`);
  }

  // Step B — build the task content.
  const serviceNames = enquiryData.services.length
    ? enquiryData.services.map(s => SERVICE_LABELS[s] || s).join(', ')
    : 'None selected';

  const taskName = `Enquiry — ${enquiryData.firstName} ${enquiryData.lastName} · ${serviceNames.slice(0, 60)}`;

  const description = [
    '--- Client Details ---',
    `Name:               ${enquiryData.firstName} ${enquiryData.lastName}`,
    `Email:              ${enquiryData.email}`,
    `Phone / WhatsApp:   ${enquiryData.phone || '—'}`,
    `Country:            ${enquiryData.country || '—'}`,
    `Payment Preference: ${PAYMENT_LABELS[enquiryData.paymentPreference] || '—'}`,
    '',
    '--- Services Requested ---',
    serviceNames,
    '',
    enquiryData.notes ? `--- Client Notes ---\n${enquiryData.notes}` : '',
    '',
    '--- System ---',
    `reCAPTCHA score: ${enquiryData.recaptchaScore}`,
    `Submitted: ${new Date().toISOString()}`,
  ].filter(line => line !== null).join('\n').trim();

  // Step C — POST to Zoho Projects create-task endpoint.
  const taskParams = new URLSearchParams({ name: taskName, description, priority: 'High' });
  if (assigneeEmail) taskParams.set('person_responsible', assigneeEmail);

  const taskRes = await fetch(
    `https://projectsapi.zoho.${dc}/restapi/portal/${portalId}/projects/${projectId}/tasks/`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Zoho-oauthtoken ${tokenData.access_token}`,
        'Content-Type':  'application/x-www-form-urlencoded',
      },
      body: taskParams,
    }
  );

  const taskData = await taskRes.json();
  if (!taskRes.ok) throw new Error(`Zoho task API error ${taskRes.status}: ${JSON.stringify(taskData)}`);

  // Zoho returns { tasks: [{ id, name, ... }] }
  const task = taskData.tasks?.[0];
  console.info('[zoho] Task created:', { id: task?.id, name: task?.name });
  return task;
}

// ── Email templates ───────────────────────────────────────────────────────────
function buildBusinessEmail(d) {
  const serviceRows = d.services.length
    ? d.services.map(s => `<tr><td style="padding:6px 0;color:#2d3748;">✓ ${SERVICE_LABELS[s]}</td></tr>`).join('')
    : '<tr><td style="padding:6px 0;color:#64748b;">None selected</td></tr>';

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>New Enquiry</title></head>
<body style="margin:0;padding:0;background:#f6f7fa;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-top:4px solid #c08a36;">
        <tr><td style="background:#0a1628;padding:28px 36px;">
          <p style="margin:0;font-family:'Cormorant Garamond',Georgia,serif;font-size:24px;color:#fff;font-weight:400;">Ocean Apex Consultancy</p>
          <p style="margin:4px 0 0;font-size:11px;color:#b0bbca;letter-spacing:1.5px;text-transform:uppercase;">New Enquiry Received</p>
        </td></tr>
        <tr><td style="padding:36px;">
          <p style="font-size:15px;color:#0a1628;margin:0 0 24px;"><strong>A new quote enquiry has been submitted via the website.</strong></p>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr><td colspan="2" style="padding-bottom:10px;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#c08a36;border-bottom:1px solid #edf0f5;">Client Details</td></tr>
            <tr><td style="padding:10px 0 4px;font-size:12px;color:#64748b;width:140px;">Name</td><td style="padding:10px 0 4px;font-size:14px;color:#2d3748;"><strong>${d.firstName} ${d.lastName}</strong></td></tr>
            <tr><td style="padding:4px 0;font-size:12px;color:#64748b;">Email</td><td style="padding:4px 0;font-size:14px;color:#2d3748;"><a href="mailto:${d.email}" style="color:#c08a36;">${d.email}</a></td></tr>
            <tr><td style="padding:4px 0;font-size:12px;color:#64748b;">Phone</td><td style="padding:4px 0;font-size:14px;color:#2d3748;">${d.phone || '—'}</td></tr>
            <tr><td style="padding:4px 0;font-size:12px;color:#64748b;">Country</td><td style="padding:4px 0;font-size:14px;color:#2d3748;">${d.country || '—'}</td></tr>
            <tr><td style="padding:4px 0;font-size:12px;color:#64748b;">Payment Preference</td><td style="padding:4px 0;font-size:14px;color:#2d3748;">${PAYMENT_LABELS[d.paymentPreference] || '—'}</td></tr>
          </table>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr><td colspan="2" style="padding-bottom:10px;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#c08a36;border-bottom:1px solid #edf0f5;">Services Requested</td></tr>
            ${serviceRows}
          </table>
          ${d.notes ? `<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;"><tr><td style="padding-bottom:10px;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#c08a36;border-bottom:1px solid #edf0f5;">Client Notes</td></tr><tr><td style="padding:12px 0;font-size:14px;color:#2d3748;line-height:1.7;white-space:pre-wrap;">${d.notes}</td></tr></table>` : ''}
          <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding-top:16px;"><a href="mailto:${d.email}?subject=Re: Your Ocean Apex Enquiry" style="display:inline-block;background:#c08a36;color:#0a1628;font-weight:700;font-size:13px;padding:14px 28px;text-decoration:none;">Reply to Client →</a></td></tr></table>
        </td></tr>
        <tr><td style="padding:20px 36px;background:#f6f7fa;border-top:1px solid #edf0f5;">
          <p style="margin:0;font-size:11px;color:#b0bbca;line-height:1.6;">Ocean Apex Consultancy Ltd. · TCSP Licence TC008172<br>Submitted: ${new Date().toISOString()} · reCAPTCHA score: ${d.recaptchaScore}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function buildClientAcknowledgement(d) {
  const serviceList = d.services.length
    ? d.services.map(s => `<li style="padding:4px 0;color:#2d3748;">${SERVICE_LABELS[s]}</li>`).join('')
    : '<li style="color:#64748b;">No specific service selected</li>';

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Enquiry Received</title></head>
<body style="margin:0;padding:0;background:#f6f7fa;font-family:'Inter',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-top:4px solid #c08a36;">
        <tr><td style="background:#0a1628;padding:28px 36px;">
          <p style="margin:0;font-family:'Cormorant Garamond',Georgia,serif;font-size:24px;color:#fff;font-weight:400;">Ocean Apex Consultancy</p>
          <p style="margin:4px 0 0;font-size:11px;color:#b0bbca;letter-spacing:1.5px;text-transform:uppercase;">Enquiry Confirmation</p>
        </td></tr>
        <tr><td style="padding:36px;">
          <p style="font-size:15px;color:#0a1628;margin:0 0 16px;">Dear ${d.firstName},</p>
          <p style="font-size:14px;color:#64748b;line-height:1.8;margin:0 0 24px;">Thank you for reaching out to Ocean Apex Consultancy. We have received your enquiry and a consultant will respond with a fixed fee proposal within <strong style="color:#0a1628;">24 business hours</strong>.</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f6f7fa;padding:20px 24px;margin-bottom:28px;">
            <tr><td style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#c08a36;padding-bottom:12px;">Services Requested</td></tr>
            <tr><td><ul style="margin:0;padding-left:18px;">${serviceList}</ul></td></tr>
          </table>
          <p style="font-size:13px;color:#64748b;line-height:2;margin:0;">📞 +852 2111 0270 &nbsp;·&nbsp; +852 2111 2030<br>✉ <a href="mailto:info@ocean-apex.com" style="color:#c08a36;">info@ocean-apex.com</a></p>
        </td></tr>
        <tr><td style="padding:20px 36px;background:#f6f7fa;border-top:1px solid #edf0f5;">
          <p style="margin:0;font-size:11px;color:#b0bbca;line-height:1.6;">Ocean Apex Consultancy Ltd. · TCSP Licence TC008172<br>This is an automated acknowledgement. Please do not reply to this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

// ── Main handler ──────────────────────────────────────────────────────────────
export default async function handler(req, res) {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '*';

  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed.' });

  // ── 1. Rate limiting ────────────────────────────────────────────────────────
  const clientIp = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown')
    .split(',')[0].trim();
  if (isRateLimited(clientIp)) {
    console.warn('[rate-limit] Blocked:', clientIp);
    return res.status(429).json({ error: 'Too many requests. Please wait a few minutes.' });
  }

  // ── 2. Parse body ───────────────────────────────────────────────────────────
  const body = req.body;
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Invalid request body.' });

  const { recaptchaToken, firstName, lastName, email, phone, country, services, notes, paymentPreference } = body;

  // ── 3. Required-field validation ────────────────────────────────────────────
  if (!recaptchaToken || typeof recaptchaToken !== 'string') return res.status(400).json({ error: 'Missing verification token.' });
  if (!firstName || !email) return res.status(400).json({ error: 'First name and email are required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return res.status(400).json({ error: 'Invalid email address.' });

  // ── 4. reCAPTCHA server-side verification ───────────────────────────────────
  let recaptchaScore = 0;
  try {
    const verifyRes = await fetch(RECAPTCHA_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret:   process.env.RECAPTCHA_SECRET_KEY,
        response: recaptchaToken,
        remoteip: clientIp,
      }),
    });
    const result = await verifyRes.json();
    console.info('[recaptcha]', { success: result.success, score: result.score, action: result.action });

    if (!result.success)                       return res.status(400).json({ error: 'Verification failed. Please try again.' });
    if (result.action !== RECAPTCHA_ACTION)    return res.status(400).json({ error: 'Verification error. Please try again.' });
    if (result.score < SCORE_THRESHOLD) {
      console.warn('[recaptcha] Low score:', result.score, clientIp);
      return res.status(400).json({ error: 'Verification score too low. Please contact us directly at info@ocean-apex.com.' });
    }
    recaptchaScore = result.score;
  } catch (err) {
    console.error('[recaptcha] Request failed:', err);
    return res.status(500).json({ error: 'Verification service unavailable. Please try again.' });
  }

  // ── 5. Sanitise inputs ──────────────────────────────────────────────────────
  const allowedServices = Object.keys(SERVICE_LABELS);
  const clean = {
    firstName:         sanitize(firstName, 100),
    lastName:          sanitize(lastName, 100),
    email:             sanitizeEmail(email),
    phone:             sanitize(phone, 30),
    country:           sanitize(country, 100),
    services:          Array.isArray(services) ? services.filter(s => allowedServices.includes(s)) : [],
    notes:             sanitize(notes, 2000),
    paymentPreference: ['card', 'bank'].includes(paymentPreference) ? paymentPreference : '',
    recaptchaScore,
  };

  const businessEmail = process.env.BUSINESS_EMAIL || 'info@ocean-apex.com';
  const fromEmail     = process.env.FROM_EMAIL     || 'enquiries@ocean-apex.com';
  const serviceSubject = clean.services.length
    ? clean.services.slice(0, 2).map(s => SERVICE_LABELS[s].split('(')[0].trim()).join(', ')
      + (clean.services.length > 2 ? ` +${clean.services.length - 2} more` : '')
    : 'General Enquiry';

  // ── 6 & 7. Send emails ──────────────────────────────────────────────────────
  const resend = new Resend(process.env.RESEND_API_KEY);
  try {
    await resend.emails.send({
      from:     fromEmail,
      to:       [businessEmail],
      reply_to: clean.email,
      subject:  `New Enquiry: ${clean.firstName} ${clean.lastName} — ${serviceSubject}`,
      html:     buildBusinessEmail(clean),
    });

    await resend.emails.send({
      from:     fromEmail,
      to:       [clean.email],
      reply_to: businessEmail,
      subject:  'We received your enquiry — Ocean Apex Consultancy Ltd.',
      html:     buildClientAcknowledgement(clean),
    });

  } catch (err) {
    console.error('[email] Send failed:', err);
    return res.status(500).json({
      error: 'Your enquiry could not be delivered right now. Please contact us directly at info@ocean-apex.com or call +852 2111 0270.',
    });
  }

  // ── 8. Create Zoho Projects task (non-blocking) ─────────────────────────────
  // Only runs when all four Zoho env vars are set.
  // A Zoho failure is logged but does NOT fail the request — the email was
  // already sent and the client already sees the confirmation screen.
  const zohoConfigured = process.env.ZOHO_CLIENT_ID
    && process.env.ZOHO_CLIENT_SECRET
    && process.env.ZOHO_REFRESH_TOKEN
    && process.env.ZOHO_PORTAL_ID
    && process.env.ZOHO_PROJECT_ID;

  if (zohoConfigured) {
    createZohoTask(clean).catch(err => {
      console.error('[zoho] Task creation failed (email was sent successfully):', err.message);
    });
  }

  // ── 9. Success ──────────────────────────────────────────────────────────────
  console.info('[enquiry] Submitted successfully:', {
    name:     `${clean.firstName} ${clean.lastName}`,
    email:    clean.email,
    services: clean.services,
    zoho:     !!zohoConfigured,
  });
  return res.status(200).json({ success: true });
}
