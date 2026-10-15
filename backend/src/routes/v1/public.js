const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const { submitScan, getScanByToken, getScanStatus, getQueueStats, downloadPublicPDF, downloadPublicXML, downloadPublicJSON } = require('../../controllers/publicScanController');

// Stricter rate limiting for public scan submissions
const publicScanLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per 15 min per IP
    message: {
        success: false,
        error: { code: 'RATE_LIMIT', message: 'Too many requests. Please wait before trying again.' },
    },
});

// POST /api/v1/public/scan — Submit a new public scan
router.post('/scan', publicScanLimiter, submitScan);

// GET /api/v1/public/scan/:token — Get full scan results by token
router.get('/scan/:token', getScanByToken);

// GET /api/v1/public/scan/:token/status — Quick status polling
router.get('/scan/:token/status', getScanStatus);

// GET /api/v1/public/queue/stats — Queue monitoring
router.get('/queue/stats', getQueueStats);

// ── Export endpoints (no login required, token-protected) ──
router.get('/scan/:token/export/pdf',  downloadPublicPDF);
router.get('/scan/:token/export/xml',  downloadPublicXML);
router.get('/scan/:token/export/json', downloadPublicJSON);

module.exports = router;

