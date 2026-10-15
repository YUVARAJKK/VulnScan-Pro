require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

const config = require('./config');
const sequelize = require('./config/database');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const v1Routes = require('./routes/v1');

// Import models to register associations
require('./models');

const app = express();

// ─── Security Middleware ───
app.use(helmet());
app.use(cors({ origin: config.cors.origin, credentials: true }));

// Trust proxy only when explicitly configured (behind a reverse proxy).
// When the API is directly exposed, trusting X-Forwarded-For would let
// clients spoof their IP and bypass per-IP rate limits.
app.set('trust proxy', config.trustProxy ? 1 : false);

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { success: false, error: { code: 'RATE_LIMIT', message: 'Too many requests' } },
});
app.use('/api/', limiter);

// Auth rate limiting (stricter)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, error: { code: 'RATE_LIMIT', message: 'Too many login attempts' } },
});
app.use('/api/v1/auth/login', authLimiter);

// Email-sending endpoints (verification & password reset) — prevents email bombing
const emailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: { success: false, error: { code: 'RATE_LIMIT', message: 'Too many verification/reset emails. Please try again later.' } },
});
app.use('/api/v1/auth/resend-verification', emailLimiter);
app.use('/api/v1/auth/forgot-password', emailLimiter);

// ─── Body Parsing ───
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── Request Logging ───
app.use(morgan('combined', {
    stream: { write: (message) => logger.info(message.trim()) },
}));

// ─── API Routes ───
app.use('/api/v1', v1Routes);

// Reports are served through the authenticated downloadReport API (reportController.js)
// with path traversal protection. No static file serving needed.

// ─── 404 Handler ───
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` },
    });
});

// ─── Error Handler ───
app.use(errorHandler);

// ─── Start Server ───
const PORT = config.port;

// Prevent BullMQ Redis connection errors from crashing the app
process.on('unhandledRejection', (reason) => {
    if (reason?.code === 'ECONNREFUSED') {
        logger.warn('⚠️  Redis not available — queue features disabled');
    } else {
        logger.error('Unhandled rejection:', reason);
    }
});

const startServer = async () => {
    try {
        // Test database connection
        await sequelize.authenticate();
        logger.info('✅ Database connected');

        // Sync models (creates tables if not exist)
        await sequelize.sync({ alter: false });
        logger.info('✅ Database models synced');

        // Check Redis availability before starting workers
        const net = require('net');
        const redisAvailable = await new Promise((resolve) => {
            const client = net.connect({ host: config.redis.host, port: config.redis.port }, () => { client.end(); resolve(true); });
            client.on('error', () => resolve(false));
            client.setTimeout(2000, () => { client.destroy(); resolve(false); });
        });

        // WORKER_MODE: When the standalone worker container is running,
        // skip worker startup here to avoid processing jobs twice.
        const isWorkerMode = process.env.WORKER_MODE === 'true';
        if (redisAvailable && !isWorkerMode) {
            // ─── Internal Scan Worker (for authenticated users) ───
            try {
                require('./workers/scanWorker');
                logger.info('✅ Internal scan worker started');
            } catch (err) {
                logger.warn('⚠️  Internal scan worker could not start:', err.message);
            }

            // ─── Public Scan Worker (for public/unauthenticated scans) ───
            try {
                require('./workers/publicScanWorker');
                logger.info('✅ Public scan worker started (concurrency: 5)');
            } catch (err) {
                logger.warn('⚠️  Public scan worker could not start:', err.message);
            }

            // ─── Scan Scheduler (recurring scans) ───
            try {
                const { startScheduler } = require('./workers/scanScheduler');
                startScheduler();
                logger.info('✅ Scan scheduler started');
            } catch (err) {
                logger.warn('⚠️  Scan scheduler could not start:', err.message);
            }
        } else if (isWorkerMode) {
            logger.info('ℹ️  WORKER_MODE=true — workers run in separate containers, skipping in-process startup.');
        } else {
            logger.warn('⚠️  Redis not available — all workers & schedulers disabled. Start Redis and restart.');
        }

        // ─── Cleanup Scheduler (token/data expiry — no Redis needed) ───
        try {
            const { startCleanupScheduler } = require('./workers/cleanupScheduler');
            startCleanupScheduler();
        } catch (err) {
            logger.warn('⚠️  Cleanup scheduler could not start:', err.message);
        }

        app.listen(PORT, () => {
            logger.info(`🚀 VulnScan Pro API running on http://localhost:${PORT}`);
            logger.info(`📖 Health check: http://localhost:${PORT}/api/v1/health`);
            logger.info(`🌐 Public scan API: POST http://localhost:${PORT}/api/v1/public/scan`);
        });
    } catch (error) {
        logger.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app; // Export for testing
