const { User, Asset, Scan, Vulnerability, AuditLog } = require('../models');
const sequelize = require('../config/database');
const { Op } = require('sequelize');

/**
 * GET /dashboard/stats
 */
const getUserStats = async (req, res, next) => {
    try {
        const userId = req.user.id;

        const [totalAssets, totalScans, totalVulnerabilities] = await Promise.all([
            Asset.count({ where: { userId } }),
            Scan.count({ where: { userId } }),
            Vulnerability.count({
                include: [{ model: Scan, as: 'scan', where: { userId }, attributes: [] }],
            }),
        ]);

        // Asset health posture — healthScore/healthGrade are written by the scan
        // worker using the shared risk model (utils/riskScoring.js), so these
        // grades always match the scan report grading.
        const assets = await Asset.findAll({
            where: { userId },
            attributes: ['id', 'name', 'target', 'type', 'healthScore', 'healthGrade', 'lastScanAt'],
            order: [['lastScanAt', 'DESC']],
        });

        // Severity distribution
        const severityData = await Vulnerability.findAll({
            attributes: ['severity', [sequelize.fn('COUNT', sequelize.col('Vulnerability.id')), 'count']],
            include: [{ model: Scan, as: 'scan', where: { userId }, attributes: [] }],
            group: ['severity'],
            raw: true,
        });

        const severityDistribution = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        severityData.forEach((s) => { severityDistribution[s.severity] = parseInt(s.count); });

        // Recent scans
        const recentScans = await Scan.findAll({
            where: { userId },
            include: [{ model: Asset, as: 'asset', attributes: ['name', 'target'] }],
            order: [['createdAt', 'DESC']],
            limit: 10,
        });

        // Attach per-scan severity summaries (fixes 0-severity chips on the dashboard)
        const recentIds = recentScans.map(r => r.id);
        const sevMap = {};
        if (recentIds.length > 0) {
            const sevRows = await Vulnerability.findAll({
                where: { scanId: { [Op.in]: recentIds } },
                attributes: ['scanId', 'severity', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
                group: ['scanId', 'severity'],
                raw: true,
            });
            for (const s of sevRows) {
                if (!sevMap[s.scanId]) sevMap[s.scanId] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                if (s.severity in sevMap[s.scanId]) sevMap[s.scanId][s.severity] = parseInt(s.count);
            }
        }
        const recentScansWithSummary = recentScans.map(r => ({
            ...r.toJSON(),
            severitySummary: sevMap[r.id] || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        }));

        // Scan trend (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const scanTrend = await Scan.findAll({
            where: { userId, createdAt: { [Op.gte]: thirtyDaysAgo } },
            attributes: [
                [sequelize.fn('DATE', sequelize.col('created_at')), 'date'],
                [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
            ],
            group: [sequelize.fn('DATE', sequelize.col('created_at'))],
            order: [[sequelize.fn('DATE', sequelize.col('created_at')), 'ASC']],
            raw: true,
        });

        res.json({
            success: true,
            data: {
                totalAssets,
                totalScans,
                totalVulnerabilities,
                criticalCount: severityDistribution.critical,
                severityDistribution,
                recentScans: recentScansWithSummary,
                scanTrend,
                assets,
            },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /dashboard/admin
 */
const getAdminStats = async (req, res, next) => {
    try {
        const [totalUsers, totalScans, activeScans] = await Promise.all([
            User.count(),
            Scan.count(),
            Scan.count({ where: { status: 'running' } }),
        ]);

        res.json({
            success: true,
            data: {
                totalUsers,
                totalScans,
                activeScans,
                systemHealth: { database: 'connected', redis: 'connected' },
            },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /admin/users
 */
const getUsers = async (req, res, next) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        const { count, rows } = await User.findAndCountAll({
            attributes: { exclude: ['passwordHash', 'mfaSecret'] },
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
 * PUT /admin/users/:id
 */
const updateUser = async (req, res, next) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'User not found' } });

        const { role, isActive } = req.body;
        if (role) user.role = role;
        if (typeof isActive === 'boolean') user.isActive = isActive;
        await user.save();

        res.json({
            success: true,
            data: { id: user.id, email: user.email, role: user.role, isActive: user.isActive },
            message: 'User updated',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /admin/audit-logs
 */
const getAuditLogs = async (req, res, next) => {
    try {
        const { page = 1, limit = 50, userId, action } = req.query;
        const offset = (page - 1) * limit;

        const where = {};
        if (userId) where.userId = userId;
        if (action) where.action = action;

        const { count, rows } = await AuditLog.findAndCountAll({
            where,
            include: [{ model: User, as: 'user', attributes: ['firstName', 'lastName', 'email'] }],
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

module.exports = { getUserStats, getAdminStats, getUsers, updateUser, getAuditLogs };
