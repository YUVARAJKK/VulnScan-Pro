const cron = require('node-cron');
const { Op } = require('sequelize');
const { PublicScan, PublicVulnerability } = require('../models');
const logger = require('../utils/logger');

/**
 * Token & Expired Data Cleanup Scheduler
 * 
 * Runs every 6 hours to:
 *  1. Delete expired public scans (token expired > 7 days ago)
 *  2. Clean up orphaned vulnerabilities
 *  3. Mark stuck scans (running > 30 minutes) as failed
 */
function startCleanupScheduler() {
    // Run every 6 hours
    cron.schedule('0 */6 * * *', async () => {
        logger.info('[Cleanup] Starting scheduled cleanup...');

        try {
            // ── 1. Delete expired scans (expired > 24h ago for grace period) ──
            const expiryCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
            const expiredScans = await PublicScan.findAll({
                where: { tokenExpiresAt: { [Op.lt]: expiryCutoff } },
                attributes: ['id'],
            });

            if (expiredScans.length > 0) {
                const expiredIds = expiredScans.map((s) => s.id);

                // Delete related vulnerabilities first
                const deletedVulns = await PublicVulnerability.destroy({
                    where: { publicScanId: { [Op.in]: expiredIds } },
                });

                // Delete the expired scans
                const deletedScans = await PublicScan.destroy({
                    where: { id: { [Op.in]: expiredIds } },
                });

                logger.info(`[Cleanup] Deleted ${deletedScans} expired scans and ${deletedVulns} related vulnerabilities`);
            }

            // ── 2. Mark stuck scans as failed ──
            const stuckCutoff = new Date(Date.now() - 30 * 60 * 1000); // 30 min
            const [stuckCount] = await PublicScan.update(
                {
                    status: 'failed',
                    errorMessage: 'Scan timed out (exceeded 30 minutes)',
                    completedAt: new Date(),
                },
                {
                    where: {
                        status: 'running',
                        startedAt: { [Op.lt]: stuckCutoff },
                    },
                }
            );

            if (stuckCount > 0) {
                logger.info(`[Cleanup] Marked ${stuckCount} stuck scans as failed`);
            }

            // ── 3. Mark old queued scans as failed ──
            const queuedCutoff = new Date(Date.now() - 60 * 60 * 1000); // 1 hour
            const [queuedCount] = await PublicScan.update(
                {
                    status: 'failed',
                    errorMessage: 'Scan expired in queue (not picked up within 1 hour)',
                    completedAt: new Date(),
                },
                {
                    where: {
                        status: 'queued',
                        createdAt: { [Op.lt]: queuedCutoff },
                    },
                }
            );

            if (queuedCount > 0) {
                logger.info(`[Cleanup] Marked ${queuedCount} stale queued scans as failed`);
            }

            logger.info('[Cleanup] Cleanup completed');
        } catch (err) {
            logger.error('[Cleanup] Error during cleanup:', err.message);
        }
    });

    logger.info('✅ Cleanup scheduler started (runs every 6 hours)');
}

module.exports = { startCleanupScheduler };
