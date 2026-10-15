/**
 * RBAC (Role-Based Access Control) Middleware
 * Role hierarchy: admin > analyst > viewer
 */
const ROLE_HIERARCHY = {
    admin: 3,
    analyst: 2,
    viewer: 1,
};

/**
 * Creates middleware that checks if user has minimum required role
 * @param {string} requiredRole - Minimum role required ('admin', 'analyst', 'viewer')
 */
const authorize = (requiredRole) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
            });
        }

        const userLevel = ROLE_HIERARCHY[req.user.role] || 0;
        const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;

        if (userLevel < requiredLevel) {
            return res.status(403).json({
                success: false,
                error: {
                    code: 'FORBIDDEN',
                    message: `Role '${requiredRole}' or higher required`,
                },
            });
        }

        next();
    };
};

module.exports = authorize;
