const { AuditLog } = require('../models');

/**
 * Create an audit log entry
 */
const createAuditLog = async (userId, action, resourceType, resourceId, details, ipAddress) => {
    try {
        await AuditLog.create({
            userId,
            action,
            resourceType,
            resourceId,
            details: details || {},
            ipAddress,
        });
    } catch (error) {
        // Don't throw — audit logging should never break the main flow
        console.error('Audit log error:', error.message);
    }
};

/**
 * Middleware factory for automatic audit logging
 */
const auditMiddleware = (action, resourceType) => {
    return (req, res, next) => {
        // Hook into response finish to log after successful operations
        const originalJson = res.json.bind(res);
        res.json = function (body) {
            if (res.statusCode >= 200 && res.statusCode < 300) {
                const resourceId = body?.data?.id || req.params?.id;
                createAuditLog(
                    req.user?.id,
                    action,
                    resourceType,
                    resourceId,
                    { method: req.method, path: req.path },
                    req.ip
                );
            }
            return originalJson(body);
        };
        next();
    };
};

module.exports = { createAuditLog, auditMiddleware };
