const jwt = require('jsonwebtoken');
const config = require('../config');
const { User } = require('../models');

/**
 * JWT Authentication Middleware
 * Verifies Bearer token and attaches user to request
 */
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: { code: 'UNAUTHORIZED', message: 'Access token required' },
            });
        }

        const token = authHeader.split(' ')[1];

        const decoded = jwt.verify(token, config.jwt.secret);

        const user = await User.findByPk(decoded.userId, {
            attributes: { exclude: ['passwordHash', 'mfaSecret'] },
        });

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                error: { code: 'UNAUTHORIZED', message: 'User not found or inactive' },
            });
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: { code: 'TOKEN_EXPIRED', message: 'Token has expired' },
            });
        }
        return res.status(401).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: 'Invalid token' },
        });
    }
};

module.exports = authenticate;
