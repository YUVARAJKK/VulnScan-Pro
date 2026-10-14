const Joi = require('joi');
const path = require('path');
const fs = require('fs');
const { Report, Scan, Vulnerability, Asset } = require('../models');
const config = require('../config');
const ReportGenerator = require('../reports/ReportGenerator');

const reportSchema = Joi.object({
    scanId: Joi.string().uuid().required(),
    title: Joi.string().min(1).max(255).required(),
    format: Joi.string().valid('pdf', 'html', 'json').default('pdf'),
    template: Joi.string().valid('executive', 'technical', 'compliance', 'json_export').optional(),
});

/**
 * POST /reports
 */
const createReport = async (req, res, next) => {
    try {
        const { error, value } = reportSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        // Verify scan ownership
        // Admin can generate reports for any scan
        const scanWhere = { id: value.scanId };
        if (req.user.role !== 'admin') scanWhere.userId = req.user.id;
        const scan = await Scan.findOne({
            where: scanWhere,
            include: [
                { model: Asset, as: 'asset' },
                { model: Vulnerability, as: 'vulnerabilities' },
            ],
        });
        if (!scan) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found' } });

        const report = await Report.create({
            userId: req.user.id,
            scanId: value.scanId,
            title: value.title,
            format: value.format,
            status: 'generating',
        });

        // Generate report asynchronously
        setImmediate(async () => {
            try {
                const generator = new ReportGenerator();
                const filePath = await generator.generate(report, scan, value.format);
                const stats = fs.statSync(filePath);
                await report.update({ status: 'completed', filePath, fileSize: stats.size });
            } catch (err) {
                await report.update({ status: 'failed' });
                console.error('Report generation error:', err);
            }
        });

        res.status(202).json({
            success: true,
            data: report,
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
            include: [{ model: Scan, as: 'scan', attributes: ['id', 'scannerType'], include: [{ model: Asset, as: 'asset', attributes: ['name', 'target'] }] }],
            limit: parseInt(limit),
            offset: parseInt(offset),
            order: [['createdAt', 'DESC']],
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
 * GET /reports/:id
 */
const getReport = async (req, res, next) => {
    try {
        const where = { id: req.params.id };
        if (req.user.role !== 'admin') where.userId = req.user.id;
        const report = await Report.findOne({ where });
        if (!report) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found' } });
        res.json({ success: true, data: report });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /reports/:id/download
 */
const downloadReport = async (req, res, next) => {
    try {
        // Admin can download any report; normal users only their own
        const reportWhere = { id: req.params.id };
        if (req.user.role !== 'admin') reportWhere.userId = req.user.id;
        const report = await Report.findOne({ where: reportWhere });
        if (!report) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report not found' } });
        if (report.status !== 'completed' || !report.filePath) {
            return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Report not ready' } });
        }

        // Path traversal protection — ensure resolved path stays within reports directory
        const reportsRoot = path.resolve(config.reports.dir);
        const absolutePath = path.resolve(report.filePath);
        if (!absolutePath.startsWith(reportsRoot)) {
            return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Invalid report path' } });
        }
        if (!fs.existsSync(absolutePath)) {
            return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Report file not found on server' } });
        }

        // Sanitize filename for Content-Disposition (prevent header injection)
        const safeTitle = String(report.title || 'report').replace(/[^a-zA-Z0-9 _\-().]/g, '_');
        const contentType = report.format === 'pdf' ? 'application/pdf' : report.format === 'json' ? 'application/json' : 'text/html';
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${safeTitle}.${report.format}"`);
        fs.createReadStream(absolutePath).pipe(res);
    } catch (err) {
        next(err);
    }
};

module.exports = { createReport, getReports, getReport, downloadReport };
