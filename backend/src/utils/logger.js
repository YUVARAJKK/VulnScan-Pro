const winston = require('winston');
const path = require('path');
const config = require('../config');

// Resolve the log directory against the backend package root (not process.cwd()),
// so logs always land in backend/logs regardless of where the process was started.
const logDir = path.isAbsolute(config.logging.dir)
    ? config.logging.dir
    : path.resolve(__dirname, '..', '..', config.logging.dir);

const logger = winston.createLogger({
    level: config.logging.level,
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'vulnscan-pro' },
    transports: [
        new winston.transports.File({
            filename: path.join(logDir, 'error.log'),
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        new winston.transports.File({
            filename: path.join(logDir, 'combined.log'),
            maxsize: 5242880,
            maxFiles: 5,
        }),
    ],
});

// Console transport: colorized/simple in development, JSON formatted in production for Docker log collectors
logger.add(
    new winston.transports.Console({
        format: config.env === 'production'
            ? winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.json()
            )
            : winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
    })
);

module.exports = logger;
