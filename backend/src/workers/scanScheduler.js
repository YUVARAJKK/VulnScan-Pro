const cron = require('node-cron');
const { Queue } = require('bullmq');
const config = require('../config');
const { Scan, Asset } = require('../models');
const { Op } = require('sequelize');
const logger = require('../utils/logger');

let scanQueue = null;
function getQueue() {
    if (!scanQueue) {
        scanQueue = new Queue('scan-queue', {
            connection: { host: config.redis?.host || '127.0.0.1', port: config.redis?.port || 6379, lazyConnect: true },
        });
    }
    return scanQueue;
}

/**
 * Scan Scheduler — checks for scheduled scans and creates new jobs
 * Runs every minute and looks for scans with scheduleEnabled=true
 * that are due for re-execution based on their scheduleInterval.
 */
function startScheduler() {
    logger.info('🕐 Scan Scheduler started — checking every minute');

    cron.schedule('* * * * *', async () => {
        try {
            const now = new Date();

            // ── Stale-scan recovery ──
            // If the backend was restarted while scans were in flight their
            // BullMQ jobs are gone and the rows would sit in 'running' forever.
            // The engine updates progress continuously, so a scan whose row has
            // not been touched for more than 20 minutes (well above the 10-minute
            // PythonScanner kill timeout) is definitively dead.
            const staleCutoff = new Date(now - 20 * 60 * 1000);
            const stalled = await Scan.findAll({
                where: {
                    status: { [Op.in]: ['queued', 'running'] },
                    updatedAt: { [Op.lt]: staleCutoff },
                },
            });
            for (const scan of stalled) {
                const minutesStale = Math.round((now - scan.updatedAt) / 60000);
                logger.warn(`⏱️ Recovering stalled scan ${scan.id} (no progress for ${minutesStale} min)`);
                await scan.update({
                    status: 'failed',
                    completedAt: now,
                    errorMessage: scan.errorMessage || `Scan stalled — no progress for ${minutesStale} minutes. The worker may have restarted.`,
                });
            }
            if (stalled.length) {
                logger.info(`⏱️ ${stalled.length} stalled scan(s) recovered (marked failed — user can retry)`);
            }

            // Find all scheduled scans that are due
            const scheduledScans = await Scan.findAll({
                where: {
                    scheduleEnabled: true,
                    status: { [Op.in]: ['completed', 'failed'] }, // Only re-trigger finished scans
                },
                include: [{ model: Asset, as: 'asset' }],
            });

            for (const scan of scheduledScans) {
                const interval = scan.scheduleInterval;
                const lastRun = scan.lastScheduledAt || scan.completedAt || scan.createdAt;

                if (!lastRun || !interval) continue;

                const hoursSince = (now - new Date(lastRun)) / (1000 * 60 * 60);
                let dueHours = Infinity;

                if (interval === 'daily') dueHours = 24;
                else if (interval === 'weekly') dueHours = 168;
                else if (interval === 'monthly') dueHours = 720;

                if (hoursSince >= dueHours) {
                    logger.info(`🔄 Scheduling scan: ${scan.scannerType} → ${scan.asset?.target || 'unknown'} (${interval})`);

                    // Create a new scan job
                    const newScan = await Scan.create({
                        userId: scan.userId,
                        assetId: scan.assetId,
                        scannerType: scan.scannerType,
                        parameters: scan.parameters,
                        status: 'queued',
                        scheduleEnabled: true,
                        scheduleInterval: interval,
                    });

                    // Mark the old scan as no longer scheduled
                    await scan.update({ scheduleEnabled: false, lastScheduledAt: now });

                    // Queue the job
                    await getQueue().add('scan', {
                        scanId: newScan.id,
                        target: scan.asset?.target,
                        scannerType: scan.scannerType,
                        parameters: scan.parameters || {},
                    });

                    logger.info(`✅ Scheduled scan created: ${newScan.id}`);
                }
            }
        } catch (err) {
            logger.error('❌ Scan scheduler error:', err.message);
        }
    });
}

module.exports = { startScheduler };
