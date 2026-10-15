const Joi = require('joi');
const config = require('../config');
const { PublicScan, PublicVulnerability } = require('../models');
const { validateTarget } = require('../utils/ssrfProtection');
const logger = require('../utils/logger');
const { Op } = require('sequelize');
const { mapToMitreAttack, buildAttackMap, PHASE_ORDER } = require('../utils/mitreMapping');

// ─── BullMQ Queue — lazy initialized, only created on first scan submission ───
let publicScanQueue = null;
function getPublicScanQueue() {
    if (!publicScanQueue) {
        const { Queue } = require('bullmq');
        publicScanQueue = new Queue('public-scan-queue', {
            connection: { 
                host: config.redis.host, 
                port: config.redis.port, 
                maxRetriesPerRequest: 1, 
                enableOfflineQueue: false 
            },
            defaultJobOptions: {
                attempts: 2,
                backoff: { type: 'exponential', delay: 5000 },
                removeOnComplete: 100,
                removeOnFail: 50,
            },
        });
    }
    return publicScanQueue;
}

// ─── Validation Schemas ───
const submitScanSchema = Joi.object({
    email: Joi.string().email().max(255).required().messages({
        'string.email': 'Please enter a valid email address',
        'any.required': 'Email address is required',
    }),
    targetUrl: Joi.string().uri({ scheme: ['http', 'https'] }).max(2048).required().messages({
        'string.uri': 'Please enter a valid URL (must start with http:// or https://)',
        'any.required': 'Target URL is required',
    }),
});

/**
 * Extract hostname from a URL string
 */
function extractHostname(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    }
}

/**
 * POST /api/v1/public/scan
 * Submit a new public scan — validates, rate-limits, checks SSRF, then queues
 */
async function submitScan(req, res, next) {
    try {
        // ── Step 1: Validate input ──
        const { error, value } = submitScanSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: error.details[0].message },
            });
        }

        const { email, targetUrl } = value;
        const hostname = extractHostname(targetUrl);

        // ── Step 2: Rate limit — per email (10 scans per person per 24 hours) ──
        const recentByEmail = await PublicScan.count({
            where: {
                email,
                createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            },
        });
        if (recentByEmail >= 10) {
            return res.status(429).json({
                success: false,
                error: { code: 'RATE_LIMIT', message: 'Maximum 10 scans per email per 24 hours. Please try again later.' },
            });
        }

        // ── Step 3: Rate limit — per IP ──
        // Use req.ip only (Express honours X-Forwarded-For when TRUST_PROXY=true
        // and the API sits behind the frontend nginx). Never fall back to a raw
        // client-supplied X-Forwarded-For header — it is trivially spoofable.
        const clientIp = req.ip;
        const recentByIp = await PublicScan.count({
            where: {
                ipAddress: clientIp,
                createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            },
        });
        if (recentByIp >= 50) {
            return res.status(429).json({
                success: false,
                error: { code: 'RATE_LIMIT', message: 'Too many scans from this network. Please try again later.' },
            });
        }

        // ── Step 4: SSRF protection ──
        const ssrfCheck = await validateTarget(targetUrl);
        if (!ssrfCheck.safe) {
            logger.warn(`[SSRF] Blocked scan submission: ${targetUrl} — ${ssrfCheck.reason}`);
            return res.status(400).json({
                success: false,
                error: { code: 'INVALID_TARGET', message: ssrfCheck.reason },
            });
        }

        // ── Step 5: Create scan record ──
        const publicScan = await PublicScan.create({
            email,
            targetUrl,
            hostname,
            ipAddress: clientIp,
            status: 'queued',
        });

        // ── Step 6: Enqueue scan job via BullMQ ──
        try {
            const queue = getPublicScanQueue();
            await queue.add(
                `scan-${publicScan.id}`,
                { scanId: publicScan.id },
                { jobId: publicScan.id }
            );
        } catch (queueErr) {
            logger.warn('Redis unavailable — public scan not queued:', queueErr.message);
            await publicScan.update({ status: 'failed', errorMessage: 'Scan service temporarily unavailable.' });
            return res.status(503).json({
                success: false,
                error: { code: 'SERVICE_UNAVAILABLE', message: 'Scan service is temporarily unavailable. Please try again later.' },
            });
        }

        logger.info(`[PublicScan] Queued scan ${publicScan.id} for ${hostname} (${email})`);

        // ── Step 8: Return response ──
        res.status(201).json({
            success: true,
            data: {
                scanId: publicScan.id,
                status: 'queued',
                hostname,
                accessToken: publicScan.accessToken,
                message: 'Scan queued! You will receive an email with the report link once scanning completes.',
            },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/v1/public/scan/:token
 * Get full scan results by access token (no auth required)
 */
async function getScanByToken(req, res, next) {
    try {
        const { token } = req.params;

        if (!token || token.length < 16) {
            return res.status(400).json({
                success: false,
                error: { code: 'INVALID_TOKEN', message: 'Invalid access token' },
            });
        }

        const scan = await PublicScan.findOne({
            where: { accessToken: token },
            include: [{
                model: PublicVulnerability,
                as: 'vulnerabilities',
                order: [['severity', 'ASC']],
            }],
        });

        if (!scan) {
            return res.status(404).json({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Scan not found or link is invalid' },
            });
        }

        // Check token expiration
        if (new Date() > new Date(scan.tokenExpiresAt)) {
            return res.status(410).json({
                success: false,
                error: { code: 'EXPIRED', message: 'This report link has expired. Request a new scan.' },
            });
        }

        res.json({
            success: true,
            data: {
                id: scan.id,
                hostname: scan.hostname,
                targetUrl: scan.targetUrl,
                status: scan.status,
                progress: scan.progress,
                startedAt: scan.startedAt,
                completedAt: scan.completedAt,
                totalVulnerabilities: scan.totalVulnerabilities,
                severityCounts: scan.severityCounts,
                riskScore: scan.riskScore,
                healthScore: scan.healthScore,
                healthGrade: scan.healthGrade,
                errorMessage: scan.errorMessage,
                createdAt: scan.createdAt,
                vulnerabilities: (scan.vulnerabilities || []).map(v => ({
                    ...(v.toJSON ? v.toJSON() : v),
                    mitre: mapToMitreAttack(v),
                })),
                mitreAttackMap: buildAttackMap(scan.vulnerabilities || []),
            },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/v1/public/scan/:token/status
 * Lightweight status endpoint for polling (no vulnerability data)
 */
async function getScanStatus(req, res, next) {
    try {
        const { token } = req.params;

        const scan = await PublicScan.findOne({
            where: { accessToken: token },
            attributes: ['id', 'status', 'progress', 'totalVulnerabilities', 'severityCounts',
                'riskScore', 'healthScore', 'healthGrade', 'startedAt', 'completedAt', 'errorMessage'],
        });

        if (!scan) {
            return res.status(404).json({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Scan not found' },
            });
        }

        res.json({ success: true, data: scan });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/v1/public/queue/stats
 * Get queue statistics (for monitoring dashboards)
 */
async function getQueueStats(req, res, next) {
    try {
        let queue;
        try { queue = getPublicScanQueue(); } catch { queue = null; }

        if (!queue) {
            return res.json({ success: true, data: { available: false } });
        }

        const [waiting, active, completed, failed] = await Promise.all([
            queue.getWaitingCount(),
            queue.getActiveCount(),
            queue.getCompletedCount(),
            queue.getFailedCount(),
        ]);

        res.json({
            success: true,
            data: { available: true, waiting, active, completed, failed },
        });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /api/v1/public/scan/:token/export/pdf
 * Enterprise-grade, consulting-quality Cybersecurity Intelligence Document.
 * Layout uses measured text heights so content never overlaps or runs outside
 * the printable margins, and includes a dedicated MITRE ATT&CK attack map.
 */
async function downloadPublicPDF(req, res, next) {
    try {
        const scan = await PublicScan.findOne({
            where: { accessToken: req.params.token },
            include: [{ model: PublicVulnerability, as: 'vulnerabilities' }],
        });
        if (!scan) return res.status(404).json({ success: false, error: { message: 'Scan not found' } });
        if (scan.status !== 'completed') return res.status(400).json({ success: false, error: { message: 'Report not ready yet' } });

        const PDFDocument = require('pdfkit');
        const vulns = (scan.vulnerabilities || []).sort((a, b) => {
            const w = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            return (w[a.severity] ?? 5) - (w[b.severity] ?? 5);
        });
        const counts = scan.severityCounts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        const total = vulns.length;
        const riskScore = scan.riskScore || 0;
        const grade = scan.healthGrade || 'N/A';
        const threatLevel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MODERATE' : riskScore >= 10 ? 'LOW' : 'SECURE';
        const threatColors = { CRITICAL: '#b91c1c', HIGH: '#c2410c', MODERATE: '#b45309', LOW: '#1e40af', SECURE: '#15803d' };
        const sevColors = { critical: '#b91c1c', high: '#c2410c', medium: '#b45309', low: '#15803d', info: '#475569' };
        const sevBg = { critical: '#fef2f2', high: '#fff7ed', medium: '#fffbeb', low: '#f0fdf4', info: '#f8fafc' };
        const attackMap = buildAttackMap(vulns);

        const doc = new PDFDocument({ margin: 0, size: 'A4', info: { Title: 'Vulnerability Assessment Report', Author: 'VulnScan Pro', Subject: scan.hostname } });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="VulnScan-Report-${scan.hostname}.pdf"`);
        doc.pipe(res);

        const W = 595, H = 842, M = 50;
        const CONTENT_TOP = 80;
        const CONTENT_BOTTOM = H - 55; // keep clear of the 40pt footer band

        const trunc = (value, max) => {
            const s = String(value || '');
            return s.length > max ? s.slice(0, max - 1) + '…' : s;
        };

        // Measure & draw helpers — every advance is based on real rendered height
        const measure = (text, size, fontName, width, gap = 2) => {
            doc.fontSize(size).font(fontName);
            return doc.heightOfString(String(text || ''), { width, lineGap: gap });
        };
        const draw = (text, x, y, size, fontName, color, width, gap = 2) => {
            doc.fontSize(size).fillColor(color).font(fontName);
            doc.text(String(text || ''), x, y, { width, lineGap: gap });
            return doc.heightOfString(String(text || ''), { width, lineGap: gap });
        };
        const pageHeader = (title, subtitle) => {
            doc.rect(0, 0, W, 60).fill('#0f172a');
            doc.fontSize(15).fillColor('#ffffff').font('Helvetica-Bold').text(title, M, 22);
            if (subtitle) doc.fontSize(9).fillColor('#94a3b8').text(subtitle, M, 42);
        };

        let pageNum = 2; // page 1 = cover (no footer), page 2 = executive summary
        const addFooter = () => {
            doc.rect(0, H - 40, W, 40).fill('#0f172a');
            doc.fontSize(8).fillColor('#94a3b8').text('VulnScan Pro  |  Confidential', M, H - 25);
            doc.fontSize(8).fillColor('#94a3b8').text(`Page ${pageNum}`, W - M - 30, H - 25);
            pageNum++;
        };

        // ════════════════════════════════════════════════════
        // PAGE 1 — COVER
        // ════════════════════════════════════════════════════
        doc.rect(0, 0, W, 300).fill('#0f172a');

        // Report type eyebrow
        doc.fontSize(9).fillColor('#94a3b8').font('Helvetica-Bold').text('VULNERABILITY ASSESSMENT REPORT', 0, 120, { align: 'center', width: W, letterSpacing: 2 });

        // Title — shrink + wrap safely inside margins so it never hits the badge
        let host = scan.hostname || scan.targetUrl;
        let hostSize = 26;
        if (String(host).length > 34) hostSize = 20;
        if (String(host).length > 60) host = String(host).slice(0, 60) + '…';
        doc.fontSize(26).fillColor('#ffffff').font('Helvetica-Bold').text('Security Assessment of', 0, 146, { align: 'center', width: W });
        const hostH = measure(host, hostSize, 'Helvetica-Bold', W - M * 2);
        doc.fontSize(hostSize).fillColor('#ffffff').font('Helvetica-Bold').text(host, M, 184, { align: 'center', width: W - M * 2, lineGap: 2 });

        // Classification badge
        doc.rect(W / 2 - 55, 244, 110, 22).fill('#b91c1c');
        doc.fontSize(9).fillColor('#ffffff').font('Helvetica-Bold').text('CONFIDENTIAL', W / 2 - 55, 249, { width: 110, align: 'center' });

        // Accent rule
        doc.rect(M, 284, W - M * 2, 1.5).fill('#1e40af');

        // Meta box — dynamic height so long values wrap inside the box
        const metaRows = [
            ['Target Asset', scan.targetUrl],
            ['Hostname', scan.hostname],
            ['Scan Date', new Date(scan.createdAt).toUTCString()],
            ['Scan ID', scan.id],
            ['Overall Risk', `${grade} — ${threatLevel}`],
            ['Total Findings', String(total)],
            ['Classification', 'Confidential'],
        ];
        const metaValueW = W - M * 2 - 165;
        const metaRowHs = metaRows.map(([, value]) => Math.max(20, measure(trunc(value, 140), 9, 'Helvetica', metaValueW) + 6));
        const metaTop = 308;
        const metaH = 20 + metaRowHs.reduce((a, b) => a + b, 0);
        doc.rect(M, metaTop, W - M * 2, metaH).fill('#f8fafc').stroke('#e2e8f0');
        let my = metaTop + 10;
        metaRows.forEach(([label, value], i) => {
            doc.fontSize(9).fillColor('#64748b').font('Helvetica-Bold').text(label.toUpperCase(), M + 15, my);
            draw(trunc(value, 140), M + 140, my, 9, 'Helvetica', '#0f172a', metaValueW);
            my += metaRowHs[i];
        });

        // Footer
        doc.rect(0, H - 40, W, 40).fill('#0f172a');
        doc.fontSize(8).fillColor('#94a3b8').text('Generated by VulnScan Pro  |  Confidential & Proprietary  |  For Internal Use Only', 0, H - 25, { align: 'center', width: W });

        // ════════════════════════════════════════════════════
        // PAGE 2 — EXECUTIVE SUMMARY
        // ════════════════════════════════════════════════════
        doc.addPage({ margin: 0, size: 'A4' });
        pageHeader('1. EXECUTIVE SUMMARY');

        let y = CONTENT_TOP;

        // Overall Threat Level
        const tlColor = threatColors[threatLevel] || '#374151';
        doc.rect(M, y, W - M * 2, 55).fill(tlColor);
        doc.fontSize(10).fillColor('#fff').font('Helvetica-Bold').text('OVERALL THREAT LEVEL', M + 15, y + 10);
        doc.fontSize(20).fillColor('#fff').font('Helvetica-Bold').text(threatLevel, M + 15, y + 24);
        doc.fontSize(10).fillColor('#fff').font('Helvetica').text(`Risk Score: ${riskScore}/100  |  Health Grade: ${grade}`, M + 180, y + 33);
        y += 75;

        // Business impact
        const impactMsg = riskScore >= 70
            ? 'CRITICAL: The assessed system contains severe vulnerabilities that could allow unauthorized remote access, full data compromise, and complete service disruption. Immediate remediation is required.'
            : riskScore >= 50
            ? 'HIGH RISK: The system contains significant vulnerabilities that expose sensitive data and may allow unauthorized access. Urgent action is recommended.'
            : riskScore >= 30
            ? 'MODERATE RISK: Several vulnerabilities were identified that could be exploited under favorable conditions. Remediation should be scheduled promptly.'
            : total > 0
            ? 'LOW RISK: Minor vulnerabilities were identified. The system is generally secure but improvements are recommended to maintain best practices.'
            : 'SECURE: No significant vulnerabilities were detected. The system appears well-configured and up-to-date.';

        doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('BUSINESS IMPACT STATEMENT', M, y); y += 16;
        y += draw(impactMsg, M, y, 9, 'Helvetica', '#374151', W - M * 2) + 18;

        // Severity breakdown table
        doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('SEVERITY BREAKDOWN', M, y); y += 14;
        doc.rect(M, y, W - M * 2, 1).fill('#e2e8f0'); y += 8;

        const sevRows = [
            ['CRITICAL', counts.critical || 0, '#b91c1c'],
            ['HIGH', counts.high || 0, '#c2410c'],
            ['MEDIUM', counts.medium || 0, '#b45309'],
            ['LOW', counts.low || 0, '#15803d'],
            ['INFO', counts.info || 0, '#475569'],
        ];
        sevRows.forEach(([label, count, color]) => {
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            const barW = total > 0 ? Math.max((count / total) * (W - M * 2 - 180), count > 0 ? 5 : 0) : 0;
            doc.rect(M, y, 8, 14).fill(color);
            doc.fontSize(9).fillColor('#0f172a').font('Helvetica-Bold').text(label, M + 14, y + 2);
            doc.fontSize(9).fillColor('#6b7280').font('Helvetica').text(`${count} finding${count !== 1 ? 's' : ''} (${pct}%)`, M + 80, y + 2);
            if (barW > 0) doc.rect(M + 180, y + 3, barW, 8).fill(color);
            y += 22;
        });

        // Key recommendations
        y += 10;
        doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('KEY RECOMMENDATIONS', M, y); y += 14;
        const recs = [];
        if (counts.critical > 0) recs.push(`Immediately patch ${counts.critical} critical vulnerabili${counts.critical === 1 ? 'ty' : 'ties'} — these represent the highest risk.`);
        if (counts.high > 0) recs.push(`Schedule urgent remediation for ${counts.high} high-severity finding${counts.high === 1 ? '' : 's'} within 7 days.`);
        if (counts.medium > 0) recs.push(`Plan remediation for ${counts.medium} medium-severity issue${counts.medium === 1 ? '' : 's'} within 30 days.`);
        if (recs.length === 0) recs.push('Maintain your current security posture and schedule regular re-assessments.');
        recs.forEach(rec => {
            doc.rect(M, y + 2, 4, 10).fill('#1e40af');
            y += draw(rec, M + 12, y + 2, 9, 'Helvetica', '#374151', W - M * 2 - 12) + 6;
        });

        // Footer
        addFooter();

        // ════════════════════════════════════════════════════
        // PAGES 3+ — TECHNICAL FINDINGS (measured layout, no overlap)
        // ════════════════════════════════════════════════════
        if (vulns.length > 0) {
            doc.addPage({ margin: 0, size: 'A4' });
            pageHeader('2. DETAILED FINDINGS', `${total} vulnerabilities identified, sorted by severity`);

            let fy = CONTENT_TOP;
            const newFindingsPage = () => {
                addFooter();
                doc.addPage({ margin: 0, size: 'A4' });
                pageHeader('2. DETAILED FINDINGS (CONTINUED)');
                fy = CONTENT_TOP;
            };

            vulns.forEach((vuln, idx) => {
                const sev = vuln.severity || 'info';
                const color = sevColors[sev] || '#475569';
                const bg = sevBg[sev] || '#f8fafc';

                // ── measure the whole block first so the page break is exact ──
                const title = String(vuln.title || 'Unnamed Finding').slice(0, 180);
                const titleW = W - M * 2 - 16;
                const titleH = measure(title, 10, 'Helvetica-Bold', titleW);
                const stripH = titleH + 14;

                const fields = [
                    ['Affected Asset', String(vuln.affectedComponent || scan.targetUrl).slice(0, 120)],
                    ['Category', String(vuln.category || 'General')],
                ];
                if (vuln.cveId) fields.push(['CVE Reference', String(vuln.cveId).slice(0, 60)]);
                let fieldsH = 0;
                const fieldRows = fields.map(([label, value]) => {
                    const vh = measure(value, 8, 'Helvetica', W - M * 2 - 118, 1);
                    const rh = Math.max(14, vh + 4);
                    fieldsH += rh;
                    return { label, value, vh, rh };
                });

                const desc = vuln.description ? String(vuln.description).slice(0, 700) : null;
                const descH = desc ? 12 + measure(desc, 8, 'Helvetica', W - M * 2 - 16, 1) + 5 : 0;

                const remediation = vuln.remediation ? String(vuln.remediation).slice(0, 450) : null;
                const remH = remediation ? 12 + measure(remediation, 8, 'Helvetica', W - M * 2 - 16, 1) + 5 : 0;

                const mitre = mapToMitreAttack(vuln);
                const mitrePrimary = mitre.primary;
                const mitreRelated = mitre.techniques.filter(t => mitrePrimary && t.id !== mitrePrimary.id);
                const mitreLine1 = `MITRE ATT&CK: ${mitrePrimary ? `${mitrePrimary.id} — ${mitrePrimary.name} (${mitrePrimary.tactic})` : 'No mapping available'}`;
                const line1H = measure(mitreLine1, 7.5, 'Helvetica-Bold', W - M * 2 - 16, 1);
                let mitreH = line1H + 3;
                let mitreLine2 = null;
                if (mitreRelated.length) {
                    mitreLine2 = `RELATED: ${mitreRelated.slice(0, 4).map(t => `${t.id} ${t.name}`).join('  •  ')}`;
                    mitreH += measure(mitreLine2, 7, 'Helvetica', W - M * 2 - 16, 1) + 3;
                }

                const gap = 16;
                const blockH = 12 + stripH + 7 + fieldsH + descH + remH + mitreH + gap;

                if (fy + blockH > CONTENT_BOTTOM) newFindingsPage();

                // ── header strip ──
                doc.rect(M, fy, W - M * 2, 12).fill(color);
                doc.fontSize(8).fillColor('#fff').font('Helvetica-Bold')
                    .text(`#${idx + 1}  ${sev.toUpperCase()}  ${vuln.cvssScore ? `CVSS: ${vuln.cvssScore}` : ''}`, M + 8, fy + 2);
                fy += 12;

                // ── title strip ──
                doc.rect(M, fy, W - M * 2, stripH).fill(bg);
                doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text(title, M + 8, fy + 6, { width: titleW, lineGap: 2 });
                fy += stripH;

                doc.rect(M, fy, W - M * 2, 1).fill('#e2e8f0'); fy += 6;

                // ── fields ──
                fieldRows.forEach(({ label, value, vh }) => {
                    doc.fontSize(8).fillColor('#64748b').font('Helvetica-Bold').text(label + ':', M + 8, fy);
                    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(value, M + 110, fy, { width: W - M * 2 - 118, lineGap: 1 });
                    fy += Math.max(14, vh + 4);
                });

                // ── description ──
                if (desc) {
                    doc.fontSize(8).fillColor('#64748b').font('Helvetica-Bold').text('Description:', M + 8, fy); fy += 12;
                    doc.fontSize(8).fillColor('#374151').font('Helvetica').text(desc, M + 8, fy, { width: W - M * 2 - 16, lineGap: 1 });
                    fy += measure(desc, 8, 'Helvetica', W - M * 2 - 16, 1) + 5;
                }
                // ── remediation ──
                if (remediation) {
                    doc.rect(M + 8, fy + 1, 3, 10).fill('#15803d');
                    doc.fontSize(8).fillColor('#64748b').font('Helvetica-Bold').text('Remediation:', M + 16, fy); fy += 12;
                    doc.fontSize(8).fillColor('#15803d').font('Helvetica').text(remediation, M + 8, fy, { width: W - M * 2 - 16, lineGap: 1 });
                    fy += measure(remediation, 8, 'Helvetica', W - M * 2 - 16, 1) + 5;
                }

                // ── MITRE ATT&CK mapping ──
                doc.fontSize(7.5).fillColor('#1e40af').font('Helvetica-Bold').text(mitreLine1, M + 8, fy, { width: W - M * 2 - 16, lineGap: 1 });
                fy += line1H + 3;
                if (mitreLine2) {
                    doc.fontSize(7).fillColor('#64748b').font('Helvetica').text(mitreLine2, M + 8, fy, { width: W - M * 2 - 16, lineGap: 1 });
                    fy += measure(mitreLine2, 7, 'Helvetica', W - M * 2 - 16, 1) + 3;
                }

                fy += gap;
            });
            addFooter();
        }

        // ════════════════════════════════════════════════════
        // MITRE ATT&CK ATTACK MAP PAGE
        // ════════════════════════════════════════════════════
        doc.addPage({ margin: 0, size: 'A4' });
        pageHeader('3. MITRE ATT&CK ATTACK MAP', 'Tactics and techniques mapped to the MITRE ATT&CK framework (attack.mitre.org)');

        const phaseMap = new Map((attackMap.phases || []).map(p => [p.phase, p]));
        let px = M, py = CONTENT_TOP;
        const nCols = 7;
        const boxW = (W - M * 2 - (nCols - 1) * 8) / nCols;
        const boxH = 58;
        PHASE_ORDER.forEach((phase, i) => {
            if (i > 0 && i % nCols === 0) { px = M; py += boxH + 16; }
            const covered = phaseMap.has(phase);
            const techs = covered ? phaseMap.get(phase).techniqueIds : [];
            doc.rect(px, py, boxW, boxH).fill(covered ? '#1e40af' : '#f1f5f9');
            doc.rect(px, py, boxW, 4).fill(covered ? '#b91c1c' : '#cbd5e1');
            doc.fontSize(6.5).fillColor(covered ? '#ffffff' : '#94a3b8').font('Helvetica-Bold')
                .text(phase.toUpperCase(), px + 2, py + 8, { width: boxW - 4, align: 'center', lineGap: 1 });
            doc.fontSize(5.5).fillColor(covered ? '#bfdbfe' : '#cbd5e1').font('Helvetica')
                .text(techs.length ? techs.join(' · ') : '—', px + 2, py + boxH - 12, { width: boxW - 4, align: 'center' });
            if (i % nCols !== nCols - 1 && i !== PHASE_ORDER.length - 1) {
                const ax = px + boxW + 2, ay = py + boxH / 2;
                doc.polygon([ax, ay - 3.5], [ax + 5, ay], [ax, ay + 3.5]).fill('#94a3b8');
            }
            px += boxW + 8;
        });

        let ty = (py + boxH) + 26;
        doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('TECHNIQUE DISTRIBUTION', M, ty); ty += 16;

        const techCols = [
            { label: 'TECHNIQUE ID', w: 62 },
            { label: 'TECHNIQUE', w: 200 },
            { label: 'TACTIC', w: 105 },
            { label: 'FINDINGS', w: 60 },
        ];
        const drawTechHeader = () => {
            doc.rect(M, ty, W - M * 2, 18).fill('#0f172a');
            let cx = M;
            techCols.forEach(c => {
                doc.fontSize(7).fillColor('#cbd5e1').font('Helvetica-Bold').text(c.label, cx + 6, ty + 5);
                cx += c.w;
            });
            ty += 18;
        };
        const ensureTechSpace = (needed) => {
            if (ty + needed > CONTENT_BOTTOM) {
                addFooter();
                doc.addPage({ margin: 0, size: 'A4' });
                pageHeader('3. MITRE ATT&CK ATTACK MAP (CONTINUED)');
                ty = CONTENT_TOP;
                drawTechHeader();
            }
        };

        drawTechHeader();
        const techs = attackMap.techniques || [];
        if (techs.length === 0) {
            doc.fontSize(8).fillColor('#94a3b8').text('No MITRE ATT&CK techniques were mapped for this assessment.', M, ty);
            ty += 18;
        } else {
            techs.forEach((t, i) => {
                const rowH = Math.max(18, measure(t.name, 8, 'Helvetica', 200, 1) + 8);
                ensureTechSpace(rowH);
                doc.rect(M, ty, W - M * 2, rowH).fill(i % 2 === 0 ? '#f8fafc' : '#ffffff');
                doc.rect(M, ty, W - M * 2, 0.5).fill('#e2e8f0');
                doc.fontSize(8).fillColor('#1e40af').font('Helvetica-Bold').text(t.id, M + 6, ty + 4, { width: 56 });
                doc.fontSize(8).fillColor('#334155').font('Helvetica').text(t.name, M + 62, ty + 4, { width: 200, lineGap: 1 });
                doc.fontSize(7.5).fillColor('#64748b').font('Helvetica').text(t.tactic, M + 266, ty + 4, { width: 100, lineGap: 1 });
                doc.fontSize(8).fillColor(t.count >= 5 ? '#b91c1c' : '#c2410c').font('Helvetica-Bold').text(String(t.count), M + 372, ty + 4, { width: 58 });
                ty += rowH;
            });
        }
        ensureTechSpace(16);
        doc.fontSize(7).fillColor('#94a3b8').text('Mappings are correlational. Technique references: https://attack.mitre.org/techniques/', M, ty + 6);
        addFooter();

        // ════════════════════════════════════════════════════
        // LAST PAGE — REMEDIATION ROADMAP + COMPLIANCE
        // ════════════════════════════════════════════════════
        doc.addPage({ margin: 0, size: 'A4' });
        pageHeader('4. REMEDIATION ROADMAP & COMPLIANCE', 'Prioritized action plan for security teams');

        let ry = CONTENT_TOP;
        const ensureRoadSpace = (needed) => {
            if (ry + needed > CONTENT_BOTTOM) {
                addFooter();
                doc.addPage({ margin: 0, size: 'A4' });
                pageHeader('4. REMEDIATION ROADMAP (CONTINUED)');
                ry = CONTENT_TOP;
            }
        };

        const phases = [
            { label: 'PHASE 1 — IMMEDIATE (0–48 hrs)', color: '#b91c1c', items: counts.critical > 0 ? [`Patch ${counts.critical} critical vulnerabilit${counts.critical === 1 ? 'y' : 'ies'} immediately`, 'Isolate affected services if exploitation risk is confirmed', 'Notify security team and stakeholders'] : ['No critical issues — maintain monitoring'] },
            { label: 'PHASE 2 — SHORT TERM (1–7 days)', color: '#c2410c', items: counts.high > 0 ? [`Remediate ${counts.high} high-severity finding${counts.high === 1 ? '' : 's'}`, 'Apply security patches and update dependencies', 'Conduct targeted penetration test on affected endpoints'] : ['No high-severity issues identified'] },
            { label: 'PHASE 3 — SCHEDULED (30 days)', color: '#b45309', items: counts.medium > 0 ? [`Address ${counts.medium} medium-severity issue${counts.medium === 1 ? '' : 's'}`, 'Conduct security awareness training', 'Review and update security policies'] : ['No medium-severity issues identified'] },
        ];

        phases.forEach(phase => {
            const itemsH = phase.items.reduce((a, item) => a + measure(`• ${item}`, 8, 'Helvetica', W - M * 2 - 20, 1) + 6, 0);
            ensureRoadSpace(18 + itemsH + 8);
            doc.rect(M, ry, W - M * 2, 18).fill(phase.color);
            doc.fontSize(9).fillColor('#fff').font('Helvetica-Bold').text(phase.label, M + 8, ry + 4);
            ry += 18;
            phase.items.forEach(item => {
                const itemH = measure(`• ${item}`, 8, 'Helvetica', W - M * 2 - 20, 1);
                doc.fontSize(8).fillColor('#374151').font('Helvetica').text(`• ${item}`, M + 12, ry, { width: W - M * 2 - 20, lineGap: 1 });
                ry += itemH + 6;
            });
            ry += 8;
        });

        ry += 10;
        const compMap = [
            ['OWASP Top 10', 'A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration'],
            ['ISO 27001', 'A.12.6 Technical Vulnerability Management, A.14.2 Security in Development'],
            ['PCI-DSS', 'Req 6.3 Identify and protect system components, Req 11.3 Penetration Testing'],
            ['NIST CSF', 'ID.RA Risk Assessment, PR.IP Information Protection, DE.CM Continuous Monitoring'],
        ];
        ensureRoadSpace(16 + compMap.reduce((a, [, desc]) => a + Math.max(24, measure(desc, 8, 'Helvetica', W - M * 2 - 116, 1) + 12), 0));
        doc.fontSize(10).fillColor('#0f172a').font('Helvetica-Bold').text('COMPLIANCE & STANDARDS MAPPING', M, ry); ry += 16;

        compMap.forEach(([std, desc]) => {
            const rowH = Math.max(22, measure(desc, 8, 'Helvetica', W - M * 2 - 116, 1) + 12);
            ensureRoadSpace(rowH);
            doc.rect(M, ry, 100, rowH).fill('#f1f5f9');
            doc.fontSize(8).fillColor('#0f172a').font('Helvetica-Bold').text(std, M + 5, ry + 6);
            doc.fontSize(8).fillColor('#374151').font('Helvetica').text(desc, M + 108, ry + 6, { width: W - M * 2 - 116, lineGap: 1 });
            ry += rowH;
        });

        addFooter();
        doc.end();
    } catch (err) { next(err); }
}

/**
 * GET /api/v1/public/scan/:token/export/xml
 * SIEM-compatible, compliance-grade XML report
 */
async function downloadPublicXML(req, res, next) {
    try {
        const scan = await PublicScan.findOne({
            where: { accessToken: req.params.token },
            include: [{ model: PublicVulnerability, as: 'vulnerabilities' }],
        });
        if (!scan) return res.status(404).json({ success: false, error: { message: 'Scan not found' } });
        if (scan.status !== 'completed') return res.status(400).json({ success: false, error: { message: 'Report not ready yet' } });

        const esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&apos;');
        const vulns = scan.vulnerabilities || [];
        const counts = scan.severityCounts || {};
        const total = vulns.length;
        const riskScore = scan.riskScore || 0;
        const threatLevel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MODERATE' : riskScore >= 10 ? 'LOW' : 'SECURE';
        const owaspMap = { injection: 'A03:2021', headers: 'A05:2021', ssl: 'A02:2021', ports: 'A05:2021', misconfig: 'A05:2021', dns: 'A05:2021' };

        let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
        xml += `<!-- VulnScan Pro - Vulnerability Assessment Report -->\n`;
        xml += `<!-- Classification: CONFIDENTIAL -->\n`;
        xml += `<VulnerabilityAssessmentReport xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="2.0" generated="${new Date().toISOString()}">\n\n`;

        xml += `  <report_metadata>\n`;
        xml += `    <tool name="VulnScan Pro" version="1.0"/>\n`;
        xml += `    <scan_id>${esc(scan.id)}</scan_id>\n`;
        xml += `    <classification>CONFIDENTIAL</classification>\n`;
        xml += `    <generated_at>${new Date().toISOString()}</generated_at>\n`;
        xml += `  </report_metadata>\n\n`;

        xml += `  <target>\n`;
        xml += `    <url>${esc(scan.targetUrl)}</url>\n`;
        xml += `    <hostname>${esc(scan.hostname)}</hostname>\n`;
        xml += `    <scan_date>${esc(scan.createdAt)}</scan_date>\n`;
        xml += `  </target>\n\n`;

        xml += `  <executive_summary>\n`;
        xml += `    <risk_score>${riskScore}</risk_score>\n`;
        xml += `    <health_grade>${esc(scan.healthGrade)}</health_grade>\n`;
        xml += `    <threat_level>${threatLevel}</threat_level>\n`;
        xml += `    <total_findings>${total}</total_findings>\n`;
        xml += `    <severity_counts critical="${counts.critical||0}" high="${counts.high||0}" medium="${counts.medium||0}" low="${counts.low||0}" info="${counts.info||0}"/>\n`;
        xml += `  </executive_summary>\n\n`;

        xml += `  <vulnerabilities count="${total}">\n`;
        for (const v of vulns) {
            xml += `    <vulnerability id="${esc(v.id)}" severity="${esc(v.severity)}">\n`;
            xml += `      <title>${esc(v.title)}</title>\n`;
            xml += `      <cvss_score>${v.cvssScore || 0}</cvss_score>\n`;
            xml += `      <category>${esc(v.category)}</category>\n`;
            xml += `      <affected_asset>${esc(v.affectedComponent)}</affected_asset>\n`;
            xml += `      <description>${esc(v.description)}</description>\n`;
            xml += `      <impact>Exploitation of this vulnerability could lead to unauthorized access, data exposure, or service disruption.</impact>\n`;
            xml += `      <remediation>${esc(v.remediation)}</remediation>\n`;
            if (v.cveId) xml += `      <cve_id>${esc(v.cveId)}</cve_id>\n`;
            if (v.references) xml += `      <references>${esc(v.references)}</references>\n`;
            const owasp = owaspMap[v.category] || 'A05:2021';
            xml += `      <compliance>\n`;
            xml += `        <owasp_top10>${owasp}</owasp_top10>\n`;
            xml += `        <iso_27001>A.12.6</iso_27001>\n`;
            xml += `      </compliance>\n`;
            const mitre = mapToMitreAttack(v);
            xml += `      <mitre_attack>\n`;
            xml += `        <tactics>${esc(mitre.tactics.join(', '))}</tactics>\n`;
            xml += `        <techniques>\n`;
            mitre.techniques.forEach(t => {
                xml += `          <technique id="${esc(t.id)}" tactic="${esc(t.tactic)}">${esc(t.name)}</technique>\n`;
            });
            xml += `        </techniques>\n`;
            xml += `      </mitre_attack>\n`;
            xml += `    </vulnerability>\n`;
        }
        xml += `  </vulnerabilities>\n\n`;

        xml += `  <appendix>\n`;
        xml += `    <scanners_used>\n`;
        xml += `      <scanner name="VulnScan Pro Custom Python Engine" version="3.1" role="Discovery, vulnerability detection, evidence validation, risk scoring"/>\n`;
        xml += `    </scanners_used>\n`;
        xml += `  </appendix>\n`;
        xml += `</VulnerabilityAssessmentReport>`;

        res.setHeader('Content-Type', 'application/xml');
        res.setHeader('Content-Disposition', `attachment; filename="VulnScan-Report-${scan.hostname}.xml"`);
        res.send(xml);
    } catch (err) { next(err); }
}

/**
 * GET /api/v1/public/scan/:token/export/json
 * CI/CD-optimized, schema-validated JSON report
 */
async function downloadPublicJSON(req, res, next) {
    try {
        const scan = await PublicScan.findOne({
            where: { accessToken: req.params.token },
            include: [{ model: PublicVulnerability, as: 'vulnerabilities' }],
        });
        if (!scan) return res.status(404).json({ success: false, error: { message: 'Scan not found' } });
        if (scan.status !== 'completed') return res.status(400).json({ success: false, error: { message: 'Report not ready yet' } });

        const counts = scan.severityCounts || {};
        const rawVulns = scan.vulnerabilities || [];
        const total = rawVulns.length;
        const riskScore = scan.riskScore || 0;
        const threatLevel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MODERATE' : riskScore >= 10 ? 'LOW' : 'SECURE';
        const owaspMap = { injection: 'A03:2021-Injection', headers: 'A05:2021-Security Misconfiguration', ssl: 'A02:2021-Cryptographic Failures', ports: 'A05:2021-Security Misconfiguration', misconfig: 'A05:2021-Security Misconfiguration', dns: 'A05:2021-Security Misconfiguration' };

        const payload = {
            schema_version: '2.0',
            classification: 'CONFIDENTIAL',
            report_metadata: {
                tool: 'VulnScan Pro',
                version: '1.0',
                generated_at: new Date().toISOString(),
                scan_id: scan.id,
            },
            target: {
                url: scan.targetUrl,
                hostname: scan.hostname,
                scan_date: scan.createdAt,
            },
            executive_summary: {
                risk_score: riskScore,
                max_risk_score: 100,
                health_grade: scan.healthGrade,
                threat_level: threatLevel,
                total_findings: total,
                severity_counts: {
                    critical: counts.critical || 0,
                    high: counts.high || 0,
                    medium: counts.medium || 0,
                    low: counts.low || 0,
                    info: counts.info || 0,
                },
                business_impact: riskScore >= 70
                    ? 'CRITICAL: Severe vulnerabilities detected. Immediate remediation required.'
                    : riskScore >= 50
                    ? 'HIGH RISK: Significant vulnerabilities found. Urgent action recommended.'
                    : 'System is generally secure. Scheduled maintenance recommended.',
            },
            vulnerabilities: rawVulns
                .sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[a.severity] ?? 5) - ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[b.severity] ?? 5))
                .map(v => {
                    const mitre = mapToMitreAttack(v);
                    return {
                        id: v.id,
                        title: v.title,
                        severity: v.severity,
                        cvss_score: v.cvssScore || 0,
                        category: v.category,
                        affected_asset: v.affectedComponent,
                        description: v.description,
                        impact: 'Exploitation could lead to unauthorized access, data exposure, or service disruption.',
                        remediation: v.remediation,
                        references: {
                            cve_id: v.cveId || null,
                            owasp: owaspMap[v.category] || 'A05:2021-Security Misconfiguration',
                            iso_27001: 'A.12.6 - Technical Vulnerability Management',
                            raw: v.references || null,
                        },
                        mitre_attack: {
                            primary: mitre.primary,
                            techniques: mitre.techniques,
                            tactics: mitre.tactics,
                        },
                    };
                }),
            mitre_attack_map: buildAttackMap(rawVulns),
            remediation_roadmap: {
                phase_1_immediate: { timeframe: '0-48 hours', priority: 'CRITICAL', count: counts.critical || 0, action: 'Patch all critical vulnerabilities immediately' },
                phase_2_short_term: { timeframe: '1-7 days', priority: 'HIGH', count: counts.high || 0, action: 'Remediate high-severity findings' },
                phase_3_scheduled: { timeframe: '30 days', priority: 'MEDIUM', count: counts.medium || 0, action: 'Address medium-severity issues' },
            },
            scanners_used: ['VulnScan Pro Custom Python Engine 3.1 (discovery, detection, evidence validation, risk scoring)'],
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="VulnScan-Intelligence-Report-${scan.hostname}.json"`);
        res.json(payload);
    } catch (err) { next(err); }
}

module.exports = { submitScan, getScanByToken, getScanStatus, getQueueStats, downloadPublicPDF, downloadPublicXML, downloadPublicJSON };
