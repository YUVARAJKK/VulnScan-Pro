const { Worker } = require('bullmq');
const config = require('../config');
const { PublicScan, PublicVulnerability } = require('../models');
const { getScanner } = require('../scanners');
const emailService = require('../utils/emailService');
const logger = require('../utils/logger');
const { calculateRiskScore } = require('../utils/riskScoring');

/**
 * BullMQ Worker for Public Scans
 *
 * Processes unauthenticated public scans using the Python scanner engine.
 * The Python scanner writes results directly to PostgreSQL.
 * This worker monitors completion and sends email notifications.
 */
const publicScanWorker = new Worker(
    'public-scan-queue',
    async (job) => {
        const { scanId } = job.data;

        logger.info(`[PublicWorker] Starting public scan ${scanId}`);

        const scan = await PublicScan.findByPk(scanId);
        if (!scan) {
            logger.warn(`[PublicWorker] Scan ${scanId} not found, skipping`);
            return;
        }

        try {
            // Mark as running
            await scan.update({ status: 'running', startedAt: new Date(), progress: 5 });
            await job.updateProgress(5);

            // Update progress
            await scan.update({ progress: 10 });
            await job.updateProgress(10);

            logger.info(`[PublicWorker] [${scanId}] Invoking Python scanner for ${scan.targetUrl}`);

            // Get the Python scanner
            const scanner = getScanner('custom');

            // Run the Python scanner — it writes directly to PostgreSQL.
            // scanKind='public' makes the engine write findings/status to
            // public_vulnerabilities / public_scans so the token report can read them.
            const result = await scanner.run(scan.targetUrl, {
                scanId,
                scanKind: 'public',
                timeout: 30, // seconds — httpx request timeout
                maxConcurrent: 50,
            });

            logger.info(`[PublicWorker] Python scanner completed for ${scanId}`, result.summary || {});

            // Read results from DB (the engine already tracked mid-scan progress
            // on the public_scans row and set status to completed at 100%)

            const summary = result.summary || {};
            const severityCounts = summary.severity_counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            const totalVulns = summary.findings_count || 0;
            // Careful: health_score can legitimately be 0 — only default when missing
            const healthScore = Number.isFinite(Number(summary.health_score))
                ? Math.round(Number(summary.health_score))
                : 100;
            const healthGrade = summary.health_grade || 'A+';
            const riskScore = Number.isFinite(Number(summary.risk_score))
                ? Math.round(Number(summary.risk_score))
                : 0;

            // Update scan with results
            await scan.update({
                status: 'completed',
                completedAt: new Date(),
                progress: 100,
                totalVulnerabilities: totalVulns,
                severityCounts,
                healthScore,
                healthGrade,
                riskScore,
            });
            await job.updateProgress(100);

            // Send email notification
            try {
                if (scan.email) {
                    await emailService.sendScanComplete(scan.email, {
                        target: scan.targetUrl,
                        scannerType: 'custom',
                        totalVulns,
                        criticalCount: severityCounts.critical,
                        highCount: severityCounts.high,
                        mediumCount: severityCounts.medium,
                        lowCount: severityCounts.low,
                        infoCount: severityCounts.info,
                        scanId,
                        accessToken: scan.accessToken,
                        isPublic: true,
                    });
                    await scan.update({ emailSent: true });
                }
            } catch (emailErr) {
                logger.warn(`[PublicWorker] Email notification failed: ${emailErr.message}`);
            }

            logger.info(`[PublicWorker] Scan ${scanId} completed — ${totalVulns} vulnerabilities found`);
        } catch (error) {
            logger.error(`[PublicWorker] Scan ${scanId} failed:`, error);

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
        concurrency: 3,
    }
);

logger.info('[PublicWorker] Public scan worker started, listening on public-scan-queue (concurrency: 3)');

publicScanWorker.on('completed', (job) => {
    logger.info(`[PublicWorker] Job ${job.id} completed`);
});

publicScanWorker.on('failed', (job, err) => {
    logger.error(`[PublicWorker] Job ${job?.id} failed: ${err.message}`);
});

publicScanWorker.on('error', (err) => {
    if (err.code === 'ECONNREFUSED') {
        logger.warn('[PublicWorker] Redis not available — worker will retry');
    } else {
        logger.error('[PublicWorker] Error:', err.message);
    }
});

module.exports = publicScanWorker;
