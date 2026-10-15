const Joi = require('joi');
const path = require('path');
const fs = require('fs');
const { Report, Scan, Vulnerability, Asset, ScanMetadata, ScanPolicy, DiscoveredEndpoint } = require('../models');
const logger = require('../utils/logger');
const ReportGenerator = require('../reports/ReportGenerator');
const { reportsRoot } = ReportGenerator;

const reportSchema = Joi.object({
    scanId: Joi.string().uuid().required(),
    title: Joi.string().min(1).max(255).required(),
    format: Joi.string().valid('pdf', 'html', 'json').default('pdf'),
    template: Joi.string().valid('executive', 'technical', 'compliance', 'json_export', 'html_web').optional(),
});

function publicReport(report) {
    const row = report && typeof report.toJSON === 'function' ? report.toJSON() : { ...report };
    delete row.filePath;
    return row;
}

function isInsideReportsDir(absolutePath) {
    const root = reportsRoot();
    const rel = path.relative(root, absolutePath);
    return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

async function loadScanForReport(scanId, user) {
    const scanWhere = { id: scanId };
    if (user.role !== 'admin') scanWhere.userId = user.id;
    return Scan.findOne({
        where: scanWhere,
        include: [
            { model: Asset, as: 'asset' },
            { model: Vulnerability, as: 'vulnerabilities' },
            { model: ScanMetadata, as: 'metadata' },
            { model: ScanPolicy, as: 'policy' },
            { model: DiscoveredEndpoint, as: 'endpoints', limit: 200 },
        ],
    });
}

async function runGeneration(report, scan, format, template) {
    const generator = new ReportGenerator();
    const filePath = await generator.generate(report, scan, format, { template });
    const stats = fs.statSync(filePath);
    await report.update({
        status: 'completed',
        filePath,
        fileSize: stats.size,
        errorMessage: null,
        template: template || report.template || 'technical',
    });
}

function enqueueGeneration(report, scan, format, template) {
    setImmediate(async () => {
        try {
            await runGeneration(report, scan, format, template);
        } catch (err) {
            logger.error('Report generation error:', err);
            try {
                await report.update({
                    status: 'failed',
                    errorMessage: String(err.message || 'Report generation failed').slice(0, 2000),
                });
            } catch (updateErr) {
                logger.error('Failed to persist report failure:', updateErr);
            }
        }
    });
}

/**
 * POST /reports
 */
const createReport = async (req, res, next) => {
    try {
        const { error, value } = reportSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const scan = await loadScanForReport(value.scanId, req.user);
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        if (['queued', 'running'].includes(scan.status)) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'Scan is still in progress. Generate a report after it completes.' },
            });
        }

        const template = value.template
            || (value.format === 'json' ? 'json_export' : value.format === 'html' ? 'html_web' : 'technical');

        const report = await Report.create({
            userId: req.user.id,
            scanId: value.scanId,
            title: value.title,
            format: value.format,
            template,
            version: '1.0',
            status: 'generating',
        });

        enqueueGeneration(report, scan, value.format, template);

        res.status(202).json({
            success: true,
            data: publicReport(report),
            message: 'Report generation started',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /reports
 */
const getReports = async (req, res, next) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        const where = {};
        if (req.user.role !== 'admin') where.userId = req.user.id;

        const { count, rows } = await Report.findAndCountAll({
            where,
            include: [{ model: Scan, as: 'scan', attributes: ['id', 'scannerType', 'status'], include: [{ model: Asset, as: 'asset', attributes: ['name', 'target'] }] }],
            limit: parseInt(limit, 10),
            offset: parseInt(offset, 10),
            order: [['createdAt', 'DESC']],
        });

        res.json({
            success: true,
            data: rows.map(publicReport),
            pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total: count },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /reports/:id
 */
const getReport = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const report = await Report.findOne({
            where,
            include: [{ model: Scan, as: 'scan', attributes: ['id', 'scannerType', 'status'], include: [{ model: Asset, as: 'asset', attributes: ['name', 'target'] }] }],
        });
        if (!report) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found' } });
        res.json({ success: true, data: publicReport(report) });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /reports/:id/regenerate
 */
const regenerateReport = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const report = await Report.findOne({ where });
        if (!report) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found' } });

        const scan = await loadScanForReport(report.scanId, req.user);
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });
        if (['queued', 'running'].includes(scan.status)) {
            return res.status(400).json({
                success: false,
                error: { code: 'BAD_REQUEST', message: 'Scan is still in progress.' },
            });
        }

        await report.update({ status: 'generating', errorMessage: null });
        enqueueGeneration(report, scan, report.format, report.template || 'technical');
        res.status(202).json({ success: true, data: publicReport(report), message: 'Report regeneration started' });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /reports/:id/download
 */
const downloadReport = async (req, res, next) => {
    try {
        const reportWhere = { id: req.params.id };
        if (req.user.role !== 'admin') reportWhere.userId = req.user.id;
        const report = await Report.findOne({ where: reportWhere });
        if (!report) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found' } });
        if (report.status === 'failed') {
            return res.status(409).json({
                success: false,
                error: { code: 'GENERATION_FAILED', message: report.errorMessage || 'Report generation failed. Try regenerating it.' },
            });
        }
        if (report.status !== 'completed' || !report.filePath) {
            return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Report not ready' } });
        }

        const absolutePath = path.resolve(report.filePath);
        if (!isInsideReportsDir(absolutePath)) {
            return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Invalid report path' } });
        }
        if (!fs.existsSync(absolutePath)) {
            return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report file not found on server' } });
        }

        const safeTitle = String(report.title || 'report').replace(/[^a-zA-Z0-9 _\-().]/g, '_');
        const contentType = report.format === 'pdf'
            ? 'application/pdf'
            : report.format === 'json'
                ? 'application/json'
                : 'text/html; charset=utf-8';
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.${report.format}"`);
        fs.createReadStream(absolutePath).pipe(res);
    } catch (err) {
        next(err);
    }
};

module.exports = {
    createReport,
    getReports,
    getReport,
    downloadReport,
    regenerateReport,
    publicReport,
    isInsideReportsDir,
    runGeneration,
};
