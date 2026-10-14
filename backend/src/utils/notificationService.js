const nodemailer = require('nodemailer');
const logger = require('./logger');

/**
 * Notification Service — sends email alerts for scan results
 * Uses nodemailer with SMTP (or Ethereal for testing)
 */
class NotificationService {
    constructor() {
        this.transporter = null;
        this._init();
    }

    async _init() {
        try {
            // Use environment config or Ethereal test account
            if (process.env.SMTP_HOST) {
                this.transporter = nodemailer.createTransport({
                    host: process.env.SMTP_HOST,
                    port: parseInt(process.env.SMTP_PORT || '587'),
                    secure: process.env.SMTP_SECURE === 'true',
                    auth: {
                        user: process.env.SMTP_USER,
                        pass: process.env.SMTP_PASS,
                    },
                });
            } else {
                // Create Ethereal test account (for development)
                const testAccount = await nodemailer.createTestAccount();
                this.transporter = nodemailer.createTransport({
                    host: testAccount.smtp.host,
                    port: testAccount.smtp.port,
                    secure: testAccount.smtp.secure,
                    auth: { user: testAccount.user, pass: testAccount.pass },
                });
                logger.info('📧 Ethereal test email: ' + testAccount.user);
            }
        } catch (err) {
            logger.warn('📧 Email notifications disabled:', err.message);
        }
    }

    /**
     * Send scan completion notification
     */
    async sendScanComplete(userEmail, scanData) {
        if (!this.transporter) return;

        const { target, scannerType, totalVulns, criticalCount, highCount, scanId } = scanData;

        const severityEmoji = criticalCount > 0 ? '🚨' : highCount > 0 ? '⚠️' : '✅';
        const subject = `${severityEmoji} Scan Complete: ${target} — ${totalVulns} finding(s)`;

        const html = `
<!DOCTYPE html>
<html>
<head><style>
    body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; padding: 32px; }
    .header { background: linear-gradient(135deg, #6366f1, #8b5cf6); padding: 24px; border-radius: 12px 12px 0 0; text-align: center; }
    .header h1 { margin: 0; color: white; font-size: 20px; }
    .body { background: #1e293b; padding: 24px; border-radius: 0 0 12px 12px; }
    .stat { display: inline-block; padding: 12px 20px; margin: 4px; border-radius: 8px; text-align: center; min-width: 80px; }
    .stat-critical { background: #dc2626; color: white; }
    .stat-high { background: #ea580c; color: white; }
    .stat-medium { background: #ca8a04; color: white; }
    .stat-low { background: #2563eb; color: white; }
    .stat-info { background: #475569; color: white; }
    .stat .num { font-size: 28px; font-weight: bold; }
    .stat .label { font-size: 11px; text-transform: uppercase; opacity: 0.8; }
    .meta { color: #94a3b8; font-size: 13px; margin-top: 16px; }
    .footer { text-align: center; color: #64748b; font-size: 12px; padding: 16px; }
</style></head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ VulnScan Pro — Scan Complete</h1>
    </div>
    <div class="body">
        <p style="margin-top:0; color:#94a3b8;">Target: <strong style="color:white;">${target}</strong></p>
        <p style="color:#94a3b8;">Scanner: <strong style="color:white;">${scannerType.toUpperCase()}</strong></p>

        <div style="text-align:center; margin: 20px 0;">
            <div class="stat stat-critical"><div class="num">${criticalCount}</div><div class="label">Critical</div></div>
            <div class="stat stat-high"><div class="num">${highCount}</div><div class="label">High</div></div>
            <div class="stat stat-medium"><div class="num">${scanData.mediumCount || 0}</div><div class="label">Medium</div></div>
            <div class="stat stat-low"><div class="num">${scanData.lowCount || 0}</div><div class="label">Low</div></div>
            <div class="stat stat-info"><div class="num">${scanData.infoCount || 0}</div><div class="label">Info</div></div>
        </div>

        <p class="meta">Total findings: <strong>${totalVulns}</strong></p>
        <p class="meta">Scan ID: ${scanId}</p>
        <p class="meta">Completed: ${new Date().toLocaleString()}</p>

        ${criticalCount > 0 ? '<p style="color:#ef4444; font-weight:bold; margin-top:16px;">⚠️ CRITICAL vulnerabilities detected — immediate action required!</p>' : ''}
    </div>
    <div class="footer">
        <p>VulnScan Pro — Integrated Vulnerability Scanning & Reporting</p>
    </div>
</div>
</body>
</html>`;

        try {
            const info = await this.transporter.sendMail({
                from: process.env.SMTP_FROM || '"VulnScan Pro" <alerts@vulnscan.pro>',
                to: userEmail,
                subject,
                html,
            });

            logger.info(`📧 Email sent: ${info.messageId}`);
            // For Ethereal: show preview URL
            const previewUrl = nodemailer.getTestMessageUrl(info);
            if (previewUrl) logger.info(`📧 Preview: ${previewUrl}`);
        } catch (err) {
            logger.error(`📧 Email send failed: ${err.message}`);
        }
    }
}

module.exports = new NotificationService();
