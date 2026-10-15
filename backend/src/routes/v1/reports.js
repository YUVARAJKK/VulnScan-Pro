const router = require('express').Router();
const auth = require('../../middleware/auth');
const authorize = require('../../middleware/rbac');
const { createReport, getReports, getReport, downloadReport, regenerateReport } = require('../../controllers/reportController');

router.use(auth);
router.use(authorize('viewer'));

router.post('/', createReport);
router.get('/', getReports);
router.get('/:id', getReport);
router.post('/:id/regenerate', regenerateReport);
router.get('/:id/download', downloadReport);

module.exports = router;
