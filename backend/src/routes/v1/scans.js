const router = require('express').Router();
const auth = require('../../middleware/auth');
const authorize = require('../../middleware/rbac');
const { getScans, getScan, createScan, cancelScan, retryScan, getScanVulnerabilities, updateVulnStatus, exportScan, toggleSchedule, getAiRemediation } = require('../../controllers/scanController');

router.use(auth);

// ─── Routes with literal path segments MUST come before /:id ───
// Otherwise Express treats "vulnerabilities" as the :id parameter
router.patch('/vulnerabilities/:id/status', authorize('viewer'), updateVulnStatus);
router.get('/vulnerabilities/:vulnId/ai-remediation', authorize('viewer'), getAiRemediation);

router.get('/', authorize('viewer'), getScans);
router.get('/:id', authorize('viewer'), getScan);
router.post('/', authorize('viewer'), createScan); // every registered user can run scans
router.post('/:id/cancel', authorize('viewer'), cancelScan);
router.post('/:id/retry', authorize('viewer'), retryScan);
router.get('/:id/vulnerabilities', authorize('viewer'), getScanVulnerabilities);
router.get('/:id/export', authorize('viewer'), exportScan);
router.put('/:id/schedule', authorize('viewer'), toggleSchedule);

module.exports = router;
