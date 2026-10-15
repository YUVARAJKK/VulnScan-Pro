const logger = require('../utils/logger');

/**
 * Global error handling middleware
 */
const errorHandler = (err, req, res, _next) => {
    logger.error('Unhandled error:', {
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
    });

    // Sequelize validation errors
    if (err.name === 'SequelizeValidationError') {
        return res.status(400).json({
            success: false,
            error: {
                code: 'VALIDATION_ERROR',
                message: 'Validation failed',
                details: err.errors.map((e) => ({
                    field: e.path,
                    message: e.message,
                })),
            },
        });
    }

    // Sequelize unique constraint errors
    if (err.name === 'SequelizeUniqueConstraintError') {
        return res.status(409).json({
            success: false,
            error: {
                code: 'CONFLICT',
                message: 'Resource already exists',
                details: err.errors.map((e) => ({
                    field: e.path,
                    message: e.message,
                })),
            },
        });
    }

    // Joi validation errors
    if (err.isJoi) {
        return res.status(400).json({
            success: false,
            error: {
                code: 'VALIDATION_ERROR',
                message: err.details[0].message,
                details: err.details.map((d) => ({
                    field: d.path.join('.'),
                    message: d.message,
                })),
            },
        });
    }

    // Default 500 error
    const statusCode = err.statusCode || 500;
    const message =
        process.env.NODE_ENV === 'production'
            ? 'Internal server error'
            : err.message;

    res.status(statusCode).json({
        success: false,
        error: {
            code: 'INTERNAL_ERROR',
            message,
        },
    });
};

module.exports = errorHandler;
