const Joi = require('joi');
const config = require('../config');
const { Scan, Asset, Vulnerability } = require('../models');
const { Op } = require('sequelize');
const sequelize = require('../config/database');
const logger = require('../utils/logger');
const { generateRemediation } = require('../utils/aiRemediationEngine');
const { validateTarget } = require('../utils/ssrfProtection');

// BullMQ scan queue — truly lazy, only created on first actual use
let _scanQueue = null;
function getScanQueue() {
    if (!_scanQueue) {
        const { Queue } = require('bullmq');
        _scanQueue = new Queue('scan-queue', {
            connection: { host: config.redis.host, port: config.redis.port, maxRetriesPerRequest: null },
        });
    }
    return _scanQueue;
}

const scanSchema = Joi.object({
    assetId: Joi.string().uuid().allow(null, ''),
    target: Joi.string().max(500).allow(null, ''),
    scannerType: Joi.string().valid('custom').default('custom'),
    parameters: Joi.object().default({}),
    policyId: Joi.string().uuid().allow(null),
    scheduleEnabled: Joi.boolean().default(false),
    scheduleInterval: Joi.string().valid('daily', 'weekly', 'monthly').allow(null),
}).or('assetId', 'target');

/**
 * GET /scans
 */
const getScans = async (req, res, next) => {
    try {
        const { page = 1, limit = 20, status, scannerType } = req.query;
        const offset = (page - 1) * limit;

        const where = {};
        if (req.user.role !== 'admin') where.userId = req.user.id;
        if (status) where.status = status;
        if (scannerType) where.scannerType = scannerType;

        const { count, rows } = await Scan.findAndCountAll({
            where,
            include: [{ model: Asset, as: 'asset', attributes: ['id', 'name', 'target', 'type'] }],
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['createdAt', 'DESC']],
        });

        // Attach per-scan severity summaries in one grouped query (fixes 0-severity display)
        const scanIds = rows.map(r => r.id);
        const sevMap = {};
        if (scanIds.length > 0) {
            const sevRows = await Vulnerability.findAll({
                where: { scanId: { [Op.in]: scanIds } },
                attributes: ['scanId', 'severity', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
                group: ['scanId', 'severity'],
                raw: true,
            });
            for (const s of sevRows) {
                if (!sevMap[s.scanId]) sevMap[s.scanId] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                if (s.severity in sevMap[s.scanId]) sevMap[s.scanId][s.severity] = parseInt(s.count);
            }
        }
        const data = rows.map(r => ({
            ...r.toJSON(),
            severitySummary: sevMap[r.id] || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        }));

        res.json({
            success: true,
            data,
            pagination: { page: parseInt(page), limit: parseInt(limit), total: count },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /scans/:id
 */
const getScan = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;

        const scan = await Scan.findOne({
            where,
            include: [{ model: Asset, as: 'asset', attributes: ['id', 'name', 'target', 'type'] }],
        });

        if (!scan) {
            return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });
        }

        // Get severity distribution
        const severitySummary = await Vulnerability.findAll({
            where: { scanId: scan.id },
            attributes: ['severity', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
            group: ['severity'],
            raw: true,
        });

        const distribution = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        severitySummary.forEach((s) => { distribution[s.severity] = parseInt(s.count); });

        res.json({
            success: true,
            data: { ...scan.toJSON(), severitySummary: distribution },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * Detect asset type from target string
 */
function detectAssetType(target) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return 'ip';
    if (/\/\d{1,2}$/.test(target)) return 'subnet';
    return 'domain';
}

/**
 * POST /scans
 * Accepts either { assetId } or { target } (direct URL input)
 */
const createScan = async (req, res, next) => {
    try {
        const { error, value } = scanSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        // ── Daily scan limit: 10 scans per account per 24 hours ──
        const recentByUser = await Scan.count({
            where: {
                userId: req.user.id,
                createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            },
        });
        if (recentByUser >= 10) {
            return res.status(429).json({
                success: false,
                error: { code: 'RATE_LIMIT', message: 'Maximum 10 scans per account per 24 hours. Please try again later.' },
            });
        }

        let asset;

        if (value.assetId) {
            // Use existing asset
            const where = { id: value.assetId };
            if (req.user.role !== 'admin') where.userId = req.user.id;
            asset = await Asset.findOne({ where });
            if (!asset) {
                return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Asset not found' } });
            }
        } else {
            // Auto-create asset from direct target URL
            let target = value.target.trim();
            // Strip protocol for clean target
            const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];

            // SSRF protection — block scans to internal/private networks
            const ssrfCheck = await validateTarget(target);
            if (!ssrfCheck.safe) {
                return res.status(400).json({
                    success: false,
                    error: { code: 'SSRF_BLOCKED', message: ssrfCheck.reason || 'Target not allowed' },
                });
            }

            const assetType = detectAssetType(cleanTarget);

            // Re-use existing asset if same target exists
            [asset] = await Asset.findOrCreate({
                where: { target: cleanTarget, userId: req.user.id },
                defaults: {
                    name: cleanTarget,
                    type: assetType,
                    target: cleanTarget,
                    description: `Auto-created from scan target: ${target}`,
                    userId: req.user.id,
                },
            });
        }

        const scan = await Scan.create({
            userId: req.user.id,
            assetId: asset.id,
            scannerType: value.scannerType,
            parameters: value.parameters,
            policyId: value.policyId,
            status: 'queued',
            scheduleEnabled: value.scheduleEnabled || false,
            scheduleInterval: value.scheduleInterval || null,
        });

        // Enqueue scan job to BullMQ
        try {
            const scanQueue = getScanQueue();
            await scanQueue.add('run-scan', {
                scanId: scan.id,
                target: asset.target,
                targetType: asset.type,
                scannerType: value.scannerType,
                parameters: value.parameters,
            }, {
                attempts: 3,
                backoff: { type: 'exponential', delay: 5000 },
            });
        } catch (queueErr) {
            logger.warn('Redis unavailable — scan created but not queued:', queueErr.message);
            await scan.update({ status: 'failed', errorMessage: 'Queue service unavailable. Please try again later.' });
        }

        res.status(201).json({
            success: true,
            data: scan,
            message: 'Scan queued successfully',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /scans/:id/cancel
 */
const cancelScan = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({ where });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        if (!['queued', 'running'].includes(scan.status)) {
            return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Can only cancel queued or running scans' } });
        }

        await scan.update({ status: 'cancelled' });
        res.json({ success: true, data: scan, message: 'Scan cancelled' });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /scans/:id/retry
 */
const retryScan = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({
            where,
            include: [{ model: Asset, as: 'asset' }],
        });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        if (scan.status !== 'failed') {
            return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Can only retry failed scans' } });
        }

        await scan.update({ status: 'queued', errorMessage: null });

        try {
            const scanQueue = getScanQueue();
            await scanQueue.add('run-scan', {
                scanId: scan.id,
                target: scan.asset.target,
                targetType: scan.asset.type,
                scannerType: scan.scannerType,
                parameters: scan.parameters,
            }, {
                attempts: 3,
                backoff: { type: 'exponential', delay: 5000 },
            });
        } catch (queueErr) {
            logger.warn('Redis unavailable — retry scan not queued:', queueErr.message);
            await scan.update({ status: 'failed', errorMessage: 'Queue service unavailable.' });
        }

        res.json({ success: true, data: scan, message: 'Scan retry queued' });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /scans/:id/vulnerabilities
 */
const getScanVulnerabilities = async (req, res, next) => {
    try {
        const { page = 1, limit = 50, severity } = req.query;
        const offset = (page - 1) * limit;

        // Verify scan ownership
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({ where });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        const vulnWhere = { scanId: scan.id };
        if (severity) vulnWhere.severity = severity;

        const { count, rows } = await Vulnerability.findAndCountAll({
            where: vulnWhere,
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [
                [sequelize.literal("CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 END"), 'ASC'],
            ],
        });

        res.json({
            success: true,
            data: rows,
            pagination: { page: parseInt(page), limit: parseInt(limit), total: count },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * PATCH /vulnerabilities/:id/status
 * Update vulnerability status (open/resolved/ignored/false_positive)
 */
const updateVulnStatus = async (req, res, next) => {
    try {
        const { status } = req.body;
        if (!['open', 'resolved', 'ignored', 'false_positive'].includes(status)) {
            return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: 'Invalid status' } });
        }

        const vuln = await Vulnerability.findByPk(req.params.id, {
            include: [{ model: Scan, as: 'scan', attributes: ['userId'] }],
        });
        if (!vuln || (req.user.role !== 'admin' && vuln.scan.userId !== req.user.id)) {
            return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Vulnerability not found' } });
        }

        await vuln.update({ status });
        res.json({ success: true, data: vuln, message: `Vulnerability marked as ${status}` });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /scans/:id/export?format=csv|json
 * Export scan vulnerabilities as CSV or JSON
 */
const exportScan = async (req, res, next) => {
    try {
        const format = req.query.format || 'json';
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({
            where,
            include: [{ model: Asset, as: 'asset' }],
        });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        const vulns = await Vulnerability.findAll({
            where: { scanId: scan.id },
            order: [
                [sequelize.literal("CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 END"), 'ASC'],
            ],
            raw: true,
        });

        if (format === 'csv') {
            const headers = 'Title,Severity,CVSS Score,CVE ID,Status,Affected Component,Remediation\n';
            const rows = vulns.map((v) =>
                `"${(v.title || '').replace(/"/g, '""')}",${v.severity},${v.cvss_score || 0},${v.cve_id || ''},${v.status || 'open'},"${(v.affected_component || '').replace(/"/g, '""')}","${(v.remediation || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`
            ).join('\n');

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="scan-${scan.id.slice(0, 8)}.csv"`);
            return res.send(headers + rows);
        }

        // JSON export
        const exportData = {
            scan: { id: scan.id, target: scan.asset?.target, scanner: scan.scannerType, status: scan.status, createdAt: scan.createdAt, completedAt: scan.completedAt },
            totalVulnerabilities: vulns.length,
            vulnerabilities: vulns.map((v) => ({
                title: v.title, severity: v.severity, cvssScore: v.cvss_score, cveId: v.cve_id, status: v.status,
                affectedComponent: v.affected_component, remediation: v.remediation, references: v.references,
            })),
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${scan.id.slice(0, 8)}.json"`);
        return res.json(exportData);
    } catch (err) {
        next(err);
    }
};

/**
 * PUT /scans/:id/schedule
 * Toggle scan scheduling on/off
 */
const toggleSchedule = async (req, res, next) => {
    try {
        const { enabled, interval } = req.body;
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({ where });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        await scan.update({
            scheduleEnabled: !!enabled,
            scheduleInterval: interval || scan.scheduleInterval,
        });

        res.json({ success: true, data: scan, message: enabled ? `Scan scheduled: ${interval}` : 'Schedule disabled' });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /scans/vulnerabilities/:vulnId/ai-remediation
 * Real AI-powered remediation using pattern-matching engine
 */
const getAiRemediation = async (req, res, next) => {
    try {
        const { vulnId } = req.params;
        const vuln = await Vulnerability.findByPk(vulnId);
        if (!vuln) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Vulnerability not found' } });

        // Verify user owns the parent scan
        const where = { id: vuln.scanId };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const scan = await Scan.findOne({ where });
        if (!scan) return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });

        const result = await generateRemediation({
            title: vuln.title,
            category: vuln.category,
            description: vuln.description,
            severity: vuln.severity,
            cvssScore: vuln.cvssScore,
            cvssVector: vuln.cvssVector,
            cveId: vuln.cveId,
            affectedComponent: vuln.affectedComponent,
            rawOutput: vuln.rawOutput,
        });

        res.json({ success: true, data: result });
    } catch (err) {
        next(err);
    }
};

module.exports = { getScans, getScan, createScan, cancelScan, retryScan, getScanVulnerabilities, updateVulnStatus, exportScan, toggleSchedule, getAiRemediation };
