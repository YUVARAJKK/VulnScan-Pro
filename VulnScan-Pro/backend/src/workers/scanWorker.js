const { Worker } = require('bullmq');
const config = require('../config');
const { Scan, Vulnerability, Asset, User } = require('../models');
const { getScanner } = require('../scanners');
const logger = require('../utils/logger');
const notificationService = require('../utils/notificationService');
const { calculateRiskScore } = require('../utils/riskScoring');

/**
 * BullMQ Scan Worker
 * Picks up scan jobs from the queue, invokes the Python scanner engine,
 * monitors completion via database, computes health scores, and sends notifications.
 */
const scanWorker = new Worker(
    'scan-queue',
    async (job) => {
        const { scanId, target, targetType, scannerType, parameters } = job.data;

        logger.info(`[Worker] Starting scan ${scanId} — ${scannerType} → ${target}`);

        // Update scan status to running
        const scan = await Scan.findByPk(scanId, {
            include: [{ model: Asset, as: 'asset' }],
        });
        if (!scan || scan.status === 'cancelled') {
            logger.info(`[Worker] Scan ${scanId} was cancelled or not found, skipping`);
            return;
        }

        await scan.update({ status: 'running', startedAt: new Date() });

        try {
            // Get the Python scanner
            const scanner = getScanner('custom');

            // Run the Python scanner — it writes directly to PostgreSQL.
            // NOTE: timeout is in SECONDS (httpx request timeout), not ms —
            // the subprocess itself is killed by PythonScanner.timeout (10 min).
            const result = await scanner.run(target, {
                scanId,
                timeout: Math.min(120, Number(parameters?.timeoutSeconds) || 30),
                maxConcurrent: Math.min(100, Number(parameters?.maxConcurrent) || 50),
            });

            logger.info(`[Worker] Python scanner completed for ${scanId}`, result.summary || {});

            // Re-read scan from DB to get the updated status and vulnerability count
            await scan.reload();
            const vulnerabilityCount = scan.totalVulnerabilities || 0;

            // Fetch vulnerabilities from DB for health score calculation
            const vulnerabilities = await Vulnerability.findAll({
                where: { scanId },
            });

            // ═══ HEALTH SCORE ═══
            if (scan.asset && vulnerabilities.length > 0) {
                const vulnData = vulnerabilities.map(v => ({
                    severity: v.severity,
                    cvssScore: v.cvssScore,
                }));
                const { riskScore, healthScore, grade } = calculateRiskScore(vulnData);
                await scan.asset.update({
                    healthScore,
                    healthGrade: grade,
                    lastScanAt: new Date(),
                });
                logger.info(`[Worker] Asset ${scan.asset.target} health: ${grade} (${healthScore}/100, risk ${riskScore})`);
            }

            // ═══ EMAIL NOTIFICATION ═══
            const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            vulnerabilities.forEach(v => {
                if (severityCounts[v.severity] !== undefined) severityCounts[v.severity]++;
            });

            try {
                const user = await User.findByPk(scan.userId);
                if (user && (severityCounts.critical > 0 || severityCounts.high > 0)) {
                    await notificationService.sendScanComplete(user.email, {
                        target,
                        scannerType,
                        totalVulns: vulnerabilityCount,
                        criticalCount: severityCounts.critical,
                        highCount: severityCounts.high,
                        mediumCount: severityCounts.medium,
                        lowCount: severityCounts.low,
                        infoCount: severityCounts.info,
                        scanId,
                    });
                }
            } catch (emailErr) {
                logger.warn(`[Worker] Email notification failed: ${emailErr.message}`);
            }

            logger.info(`[Worker] Scan ${scanId} completed — ${vulnerabilityCount} vulnerabilities found`);
        } catch (error) {
            logger.error(`[Worker] Scan ${scanId} failed:`, error);

            await scan.update({
                status: 'failed',
                completedAt: new Date(),
                errorMessage: error.message,
            });

            throw error; // Let BullMQ handle retry
        }
    },
    {
        connection: { host: config.redis.host, port: config.redis.port },
        concurrency: 3, // Max 3 concurrent scans
    }
);

logger.info('[Worker] Scan worker started, listening on scan-queue (concurrency: 3)');

scanWorker.on('completed', (job) => {
    logger.info(`[Worker] Job ${job.id} completed`);
});

scanWorker.on('failed', (job, err) => {
    logger.error(`[Worker] Job ${job?.id} failed: ${err.message}`);
});

scanWorker.on('error', (err) => {
    if (err.code === 'ECONNREFUSED') {
        logger.warn('[Worker] Redis not available — scan worker will retry');
    } else {
        logger.error('[Worker] Error:', err.message);
    }
});

module.exports = scanWorker;
