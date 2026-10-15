const nodemailer = require('nodemailer');
const config = require('../config');
const logger = require('./logger');

/**
 * Email Service — VulnScan Pro
 * Premium dark-mode HTML email with:
 * - CVSS risk gauge (SVG)
 * - Top 3 critical findings
 * - MITRE ATT&CK tactic badges
 * - Security grade display
 * - Professional typography
 */
class EmailService {
    constructor() {
        this.transporter = null;
        this._init();
    }

    /**
     * True when a real SMTP provider is configured (vs. the Ethereal test sink
     * or no transporter at all). Used by auth flows to decide whether email
     * verification can actually be delivered — in local/dev mode without SMTP,
     * accounts are auto-verified so users are never locked out.
     */
    get isSmtpConfigured() {
        return !!(config.smtp.host && config.smtp.user);
    }

    _init() {
        if (config.smtp.host && config.smtp.user) {
            this.transporter = nodemailer.createTransport({
                host: config.smtp.host,
                port: config.smtp.port,
                secure: config.smtp.port === 465,
                auth: { user: config.smtp.user, pass: config.smtp.pass },
                tls: { rejectUnauthorized: false },
                // Explicit timeouts — without these a firewalled/blocked SMTP
                // server hangs nodemailer's default and the CMX socket freeze
                // made requests hang and logs only show a bare message.
                connectionTimeout: 15000,
                greetingTimeout: 15000,
                socketTimeout: 20000,
            });
            logger.info(`✅ Email service configured with SMTP (${config.smtp.host}:${config.smtp.port})`);
        } else {
            this._createTestTransport();
        }
    }

    async _createTestTransport() {
        try {
            const testAccount = await nodemailer.createTestAccount();
            this.transporter = nodemailer.createTransport({
                host: 'smtp.ethereal.email',
                port: 587,
                secure: false,
                auth: { user: testAccount.user, pass: testAccount.pass },
            });
            logger.info(`✅ Email service using Ethereal test account: ${testAccount.user}`);
        } catch (err) {
            logger.warn('⚠️  Email service unavailable:', err.message);
        }
    }

    /**
     * Send premium scan completion email
     */
    async sendScanReport(email, scanData) {
        if (!this.transporter) {
            logger.warn('Email transporter not available, skipping email send');
            return null;
        }

        const {
            accessToken, hostname, totalVulnerabilities,
            severityCounts, id, riskScore, healthGrade,
            topFindings = [],
        } = scanData;

        const frontendUrl = config.cors.origin || 'http://localhost:3000';
        const accessLink = `${frontendUrl}/report/${accessToken}`;
        const c = severityCounts || {};
        const criticalCount = c.critical || 0;
        const highCount = c.high || 0;
        const mediumCount = c.medium || 0;
        const lowCount = c.low || 0;
        const infoCount = c.info || 0;
        const score = riskScore || 0;
        const grade = healthGrade || 'N/A';

        // Grade configuration
        const gradeConfig = {
            'A+': { color: '#10b981', bg: 'rgba(16,185,129,0.15)', label: 'Excellent Security Posture' },
            'A':  { color: '#10b981', bg: 'rgba(16,185,129,0.12)', label: 'Strong Security Posture' },
            'B':  { color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', label: 'Good Security Posture' },
            'C':  { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  label: 'Moderate Risk' },
            'D':  { color: '#f97316', bg: 'rgba(249,115,22,0.12)', label: 'High Risk' },
            'F':  { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  label: 'Critical Risk — Action Required' },
        };
        const gc = gradeConfig[grade] || { color: '#64748b', bg: 'rgba(100,116,139,0.12)', label: 'Unknown' };

        const riskColor = criticalCount > 0 ? '#a855f7' : highCount > 0 ? '#ef4444' : mediumCount > 0 ? '#f97316' : '#10b981';
        const riskLabel = criticalCount > 0 ? 'Critical Risk' : highCount > 0 ? 'High Risk' : mediumCount > 0 ? 'Medium Risk' : 'Low Risk';

        // SVG gauge for risk score
        const gaugeAngle = Math.round((score / 100) * 180);
        const gaugeR = 52;
        const gaugeCirc = Math.PI * gaugeR;
        const gaugeDash = (score / 100) * gaugeCirc;
        const gaugeColor = score >= 75 ? '#a855f7' : score >= 50 ? '#ef4444' : score >= 25 ? '#f97316' : '#10b981';

        // Severity badge HTML helper
        const sevBadge = (label, count, color, bg) => count > 0 ? `
            <td style="text-align:center;padding:0 6px;">
                <div style="background:${bg};border:1px solid ${color}40;border-radius:10px;padding:12px 10px;min-width:56px;">
                    <div style="font-size:26px;font-weight:900;color:${color};line-height:1;">${count}</div>
                    <div style="font-size:10px;color:#94a3b8;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${label}</div>
                </div>
            </td>` : `
            <td style="text-align:center;padding:0 6px;">
                <div style="background:rgba(15,23,42,0.5);border:1px solid #1e293b;border-radius:10px;padding:12px 10px;min-width:56px;">
                    <div style="font-size:26px;font-weight:900;color:#1e293b;line-height:1;">0</div>
                    <div style="font-size:10px;color:#334155;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${label}</div>
                </div>
            </td>`;

        // Top findings section
        const sevColors = { critical: '#a855f7', high: '#ef4444', medium: '#f97316', low: '#eab308', info: '#64748b' };
        const findingsHtml = topFindings.length > 0 ? `
            <div style="margin:0 0 28px;">
                <div style="font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">⚠️ Top Findings</div>
                ${topFindings.slice(0, 3).map((f, i) => `
                <div style="background:#080f1e;border:1px solid #1e3a5f;border-left:3px solid ${sevColors[f.severity] || '#64748b'};border-radius:8px;padding:12px 16px;margin-bottom:8px;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                        <span style="background:${sevColors[f.severity] || '#64748b'}22;color:${sevColors[f.severity] || '#64748b'};font-size:9px;font-weight:800;padding:2px 7px;border-radius:4px;text-transform:uppercase;">${f.severity || 'info'}</span>
                        <span style="font-size:13px;font-weight:700;color:#e2e8f0;">${(f.title || '').slice(0, 60)}${(f.title || '').length > 60 ? '...' : ''}</span>
                    </div>
                    ${f.affectedComponent ? `<div style="font-size:11px;color:#475569;font-family:monospace;">${f.affectedComponent}</div>` : ''}
                </div>`).join('')}
            </div>` : '';

        // MITRE ATT&CK badge (shown if critical/high findings)
        const mitreBadges = criticalCount + highCount > 0 ? `
            <div style="margin:0 0 28px;">
                <div style="font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px;">🎯 Relevant MITRE ATT&CK Tactics</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                    ${criticalCount > 0 ? '<span style="background:rgba(168,85,247,0.12);border:1px solid rgba(168,85,247,0.3);color:#c4b5fd;font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;">T1190 — Initial Access</span>' : ''}
                    ${highCount > 0 ? '<span style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;">T1046 — Network Discovery</span>' : ''}
                    <span style="background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);color:#a5b4fc;font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;">T1592 — Host Recon</span>
                    ${mediumCount > 0 ? '<span style="background:rgba(249,115,22,0.12);border:1px solid rgba(249,115,22,0.3);color:#fdba74;font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;">T1040 — Network Sniffing</span>' : ''}
                </div>
            </div>` : '';

        const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="color-scheme" content="dark">
<title>VulnScan Pro — Security Report: ${hostname}</title>
</head>
<body style="margin:0;padding:0;background-color:#060d1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',Tahoma,sans-serif;">
<div style="max-width:620px;margin:0 auto;padding:24px 16px;">

    <!-- Top Status Bar -->
    <div style="background:linear-gradient(135deg,#0d1f3c,#060d1a);border:1px solid #1e3a5f;border-radius:12px;padding:10px 20px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;">
        <span style="font-size:11px;color:#475569;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;">Security Scan Report</span>
        <span style="font-size:11px;color:${gc.color};font-weight:700;background:${gc.bg};padding:3px 10px;border-radius:20px;border:1px solid ${gc.color}30;">● ${gc.label}</span>
    </div>

    <!-- Hero Header -->
    <div style="background:linear-gradient(135deg,#1a0533 0%,#0d1f3c 40%,#0a1628 100%);border:1px solid #2d1b69;border-radius:16px;padding:36px 32px;margin-bottom:20px;text-align:center;position:relative;overflow:hidden;">
        <!-- Decorative glow -->
        <div style="position:absolute;top:-40px;left:50%;transform:translateX(-50%);width:200px;height:200px;background:radial-gradient(circle,rgba(99,102,241,0.15),transparent 70%);pointer-events:none;"></div>
        
        <!-- Shield icon -->
        <div style="width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:16px;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 32px rgba(99,102,241,0.4);">
            <span style="font-size:28px;">🛡️</span>
        </div>
        
        <h1 style="color:#f1f5f9;margin:0 0 6px;font-size:28px;font-weight:900;letter-spacing:-0.5px;">VulnScan Pro</h1>
        <p style="color:#94a3b8;margin:0 0 20px;font-size:14px;">Vulnerability Assessment Complete</p>
        
        <div style="background:rgba(15,23,42,0.6);border:1px solid #1e3a5f;border-radius:10px;padding:12px 20px;display:inline-block;">
            <p style="color:#64748b;margin:0 0 2px;font-size:10px;text-transform:uppercase;letter-spacing:0.1em;font-weight:700;">Target Assessed</p>
            <p style="color:#818cf8;margin:0;font-size:18px;font-weight:800;font-family:monospace;">${hostname}</p>
        </div>
    </div>

    <!-- Risk Score + Grade Row -->
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
        <tr>
            <!-- Grade Card -->
            <td width="50%" style="padding-right:8px;">
                <div style="background:#080f1e;border:1px solid ${gc.color}40;border-radius:14px;padding:24px;text-align:center;">
                    <p style="color:#475569;margin:0 0 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;">Security Grade</p>
                    <div style="font-size:56px;font-weight:900;color:${gc.color};line-height:1;margin-bottom:8px;">${grade}</div>
                    <div style="background:${gc.bg};border:1px solid ${gc.color}30;border-radius:6px;padding:4px 12px;display:inline-block;">
                        <span style="font-size:11px;color:${gc.color};font-weight:700;">${gc.label}</span>
                    </div>
                </div>
            </td>
            <!-- Risk Score Card -->
            <td width="50%" style="padding-left:8px;">
                <div style="background:#080f1e;border:1px solid #1e3a5f;border-radius:14px;padding:24px;text-align:center;">
                    <p style="color:#475569;margin:0 0 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;">Risk Score</p>
                    <!-- SVG Gauge -->
                    <svg width="120" height="70" viewBox="0 0 120 70" style="display:block;margin:0 auto 4px;">
                        <path d="M15,60 A50,50 0 0,1 105,60" fill="none" stroke="#1e293b" stroke-width="10" stroke-linecap="round"/>
                        <path d="M15,60 A50,50 0 0,1 105,60" fill="none" stroke="${gaugeColor}" stroke-width="10" stroke-linecap="round"
                            stroke-dasharray="${gaugeDash * (gaugeCirc / (Math.PI * 52))} ${gaugeCirc}"/>
                        <text x="60" y="56" text-anchor="middle" fill="${gaugeColor}" font-size="22" font-weight="900" font-family="Inter,sans-serif">${score}</text>
                    </svg>
                    <p style="color:#475569;margin:0;font-size:11px;font-weight:600;">/ 100</p>
                    <div style="background:${riskColor}18;border:1px solid ${riskColor}30;border-radius:6px;padding:4px 12px;display:inline-block;margin-top:8px;">
                        <span style="font-size:11px;color:${riskColor};font-weight:700;">${riskLabel}</span>
                    </div>
                </div>
            </td>
        </tr>
    </table>

    <!-- Severity Breakdown -->
    <div style="background:#080f1e;border:1px solid #1e3a5f;border-radius:14px;padding:20px;margin-bottom:20px;">
        <p style="color:#475569;margin:0 0 14px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;">📊 Vulnerability Breakdown — ${totalVulnerabilities} Total Findings</p>
        <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
                ${sevBadge('Critical', criticalCount, '#a855f7', 'rgba(168,85,247,0.12)')}
                ${sevBadge('High', highCount, '#ef4444', 'rgba(239,68,68,0.12)')}
                ${sevBadge('Medium', mediumCount, '#f97316', 'rgba(249,115,22,0.12)')}
                ${sevBadge('Low', lowCount, '#eab308', 'rgba(234,179,8,0.12)')}
                ${sevBadge('Info', infoCount, '#64748b', 'rgba(100,116,139,0.12)')}
            </tr>
        </table>
    </div>

    <!-- Top Findings (if any) -->
    ${findingsHtml ? `<div style="background:#080f1e;border:1px solid #1e3a5f;border-radius:14px;padding:20px;margin-bottom:20px;">${findingsHtml}</div>` : ''}

    <!-- MITRE ATT&CK Tactics -->
    ${mitreBadges ? `<div style="background:#080f1e;border:1px solid #1e3a5f;border-radius:14px;padding:20px;margin-bottom:20px;">${mitreBadges}</div>` : ''}

    <!-- CTA Button -->
    <div style="text-align:center;margin:28px 0;">
        <a href="${accessLink}" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:12px;font-weight:800;font-size:16px;letter-spacing:0.02em;box-shadow:0 8px 32px rgba(99,102,241,0.4);">
            View Full Security Report →
        </a>
        <p style="color:#334155;font-size:11px;margin:12px 0 0;">Link expires in 7 days — do not share with unauthorized parties</p>
    </div>

    <!-- Compliance Frameworks Strip -->
    <div style="background:#080f1e;border:1px solid #1e3a5f;border-radius:12px;padding:16px 20px;margin-bottom:20px;">
        <p style="color:#334155;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 10px;">Framework Coverage</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <span style="background:#0f172a;border:1px solid #1e3a5f;color:#475569;font-size:10px;padding:3px 10px;border-radius:4px;font-weight:600;">MITRE ATT&CK v19.1</span>
            <span style="background:#0f172a;border:1px solid #1e3a5f;color:#475569;font-size:10px;padding:3px 10px;border-radius:4px;font-weight:600;">NIST CSF 2.0</span>
            <span style="background:#0f172a;border:1px solid #1e3a5f;color:#475569;font-size:10px;padding:3px 10px;border-radius:4px;font-weight:600;">OWASP Top 10 2021</span>
            <span style="background:#0f172a;border:1px solid #1e3a5f;color:#475569;font-size:10px;padding:3px 10px;border-radius:4px;font-weight:600;">MITRE D3FEND</span>
            <span style="background:#0f172a;border:1px solid #1e3a5f;color:#475569;font-size:10px;padding:3px 10px;border-radius:4px;font-weight:600;">CWE/CVE</span>
        </div>
    </div>

    <!-- Footer -->
    <div style="text-align:center;padding:16px 0;">
        <p style="color:#1e3a5f;font-size:11px;margin:0;">
            <strong style="color:#334155;">VulnScan Pro</strong> — Enterprise Vulnerability Scanning & AI Remediation
        </p>
        <p style="color:#0f1e35;font-size:10px;margin:4px 0 0;">Scan ID: ${id}</p>
    </div>

</div>
</body>
</html>`;

        try {
            const info = await this.transporter.sendMail({
                from: `"VulnScan Pro 🛡️" <${config.smtp.from}>`,
                to: email,
                subject: `🛡️ [${grade}] Security Report: ${hostname} — ${totalVulnerabilities} Findings | ${riskLabel}`,
                html: htmlBody,
                text: `VulnScan Pro — Security Report Complete\n\nTarget: ${hostname}\nGrade: ${grade}\nRisk Score: ${score}/100\nTotal Findings: ${totalVulnerabilities}\nCritical: ${criticalCount} | High: ${highCount} | Medium: ${mediumCount} | Low: ${lowCount}\n\nView Full Report: ${accessLink}\n\nVulnScan Pro — Enterprise Security Scanning`,
            });

            const previewUrl = nodemailer.getTestMessageUrl(info);
            if (previewUrl) logger.info(`📧 Email preview URL: ${previewUrl}`);
            logger.info(`📧 Premium scan report email sent to ${email}`);
            return info;
        } catch (err) {
            logger.error(`Failed to send email to ${email}: ${err.code || "ERR"} — ${err.message}${err.response ? " | " + err.response : ""}`);
            throw err;
        }
    }

    /**
     * Generic email sender (used by verification & password-reset flows)
     */
    async sendEmail(to, subject, html, text) {
        if (!this.transporter) {
            logger.warn('Email transporter not available, skipping email send');
            return null;
        }

        try {
            const info = await this.transporter.sendMail({
                from: `"VulnScan Pro 🛡️" <${config.smtp.from}>`,
                to,
                subject,
                html,
                text: text || '',
            });
            const previewUrl = nodemailer.getTestMessageUrl(info);
            if (previewUrl) logger.info(`📧 Email preview URL: ${previewUrl}`);
            logger.info(`📧 Email sent to ${to} (${subject})`);
            return info;
        } catch (err) {
            logger.error(`Failed to send email to ${to}: ${err.code || "ERR"} — ${err.message}${err.response ? " | " + err.response : ""}`);
            throw err;
        }
    }

    /**
     * Send email verification message with tokenized activation link
     */
    async sendVerificationEmail(to, { name = '', token }) {
        const frontendUrl = config.cors.origin || 'http://localhost:3000';
        const verifyLink = `${frontendUrl}/verify-email?token=${token}`;
        const displayName = name || to;

        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Verify your VulnScan Pro account</title>
</head>
<body style="margin:0;padding:0;background-color:#060d1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Tahoma,sans-serif;">
<div style="max-width:560px;margin:0 auto;padding:32px 20px;">
    <div style="background:linear-gradient(135deg,#0d1f3c,#060d1a);border:1px solid #1e3a5f;border-radius:16px;padding:40px 32px;text-align:center;">
        <div style="width:56px;height:56px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:14px;margin:0 auto 18px;display:flex;align-items:center;justify-content:center;">
            <span style="font-size:24px;">🛡️</span>
        </div>
        <h1 style="color:#f1f5f9;margin:0 0 8px;font-size:22px;font-weight:800;">Verify your email address</h1>
        <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Hi <strong style="color:#e2e8f0;">${displayName}</strong>,<br/>
            Welcome to VulnScan Pro! Click the button below to confirm your email address and activate your account.
        </p>
        <a href="${verifyLink}" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#ffffff;text-decoration:none;padding:14px 36px;border-radius:10px;font-weight:700;font-size:15px;">
            Verify Email →
        </a>
        <p style="color:#475569;font-size:12px;margin:24px 0 0;line-height:1.6;">
            This link expires in 24 hours. If you did not create this account, you can safely ignore this email.
        </p>
    </div>
    <div style="text-align:center;padding:20px 0;color:#334155;font-size:11px;">
        VulnScan Pro — Integrated Vulnerability Scanning & Reporting
    </div>
</div>
</body>
</html>`;

        return this.sendEmail(
            to,
            '🛡️ Verify your VulnScan Pro account',
            html,
            `Verify your email: ${verifyLink}\n\nThis link expires in 24 hours.`
        );
    }

    /**
     * Send password reset message with tokenized reset link
     */
    async sendPasswordResetEmail(to, { name = '', token }) {
        const frontendUrl = config.cors.origin || 'http://localhost:3000';
        const resetLink = `${frontendUrl}/reset-password?token=${token}`;
        const displayName = name || to;

        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reset your VulnScan Pro password</title>
</head>
<body style="margin:0;padding:0;background-color:#060d1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Tahoma,sans-serif;">
<div style="max-width:560px;margin:0 auto;padding:32px 20px;">
    <div style="background:linear-gradient(135deg,#0d1f3c,#060d1a);border:1px solid #1e3a5f;border-radius:16px;padding:40px 32px;text-align:center;">
        <div style="width:56px;height:56px;background:linear-gradient(135deg,#f97316,#ef4444);border-radius:14px;margin:0 auto 18px;display:flex;align-items:center;justify-content:center;">
            <span style="font-size:24px;">🔐</span>
        </div>
        <h1 style="color:#f1f5f9;margin:0 0 8px;font-size:22px;font-weight:800;">Reset your password</h1>
        <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 24px;">
            Hi <strong style="color:#e2e8f0;">${displayName}</strong>,<br/>
            We received a request to reset your password. Click the button below to choose a new one.
        </p>
        <a href="${resetLink}" style="display:inline-block;background:linear-gradient(135deg,#f97316,#ef4444);color:#ffffff;text-decoration:none;padding:14px 36px;border-radius:10px;font-weight:700;font-size:15px;">
            Reset Password →
        </a>
        <p style="color:#475569;font-size:12px;margin:24px 0 0;line-height:1.6;">
            This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.
        </p>
    </div>
    <div style="text-align:center;padding:20px 0;color:#334155;font-size:11px;">
        VulnScan Pro — Integrated Vulnerability Scanning & Reporting
    </div>
</div>
</body>
</html>`;

        return this.sendEmail(
            to,
            '🔐 Reset your VulnScan Pro password',
            html,
            `Reset your password: ${resetLink}\n\nThis link expires in 1 hour.`
        );
    }
}

module.exports = new EmailService();
