const router = require('express').Router();
const auth = require('../../middleware/auth');
const authorize = require('../../middleware/rbac');
const { getUserStats, getAdminStats, getUsers, updateUser, getAuditLogs } = require('../../controllers/dashboardController');

// Dashboard
router.get('/dashboard/stats', auth, authorize('viewer'), getUserStats);
router.get('/dashboard/admin', auth, authorize('admin'), getAdminStats);

// Admin
router.get('/admin/users', auth, authorize('admin'), getUsers);
router.put('/admin/users/:id', auth, authorize('admin'), updateUser);
router.get('/admin/audit-logs', auth, authorize('admin'), getAuditLogs);

module.exports = router;
