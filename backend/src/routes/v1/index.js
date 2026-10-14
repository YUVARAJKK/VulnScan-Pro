const router = require('express').Router();

const authRoutes = require('./auth');
const assetRoutes = require('./assets');
const scanRoutes = require('./scans');
const reportRoutes = require('./reports');
const dashboardRoutes = require('./dashboard');
const publicRoutes = require('./public');

router.use('/auth', authRoutes);
router.use('/assets', assetRoutes);
router.use('/scans', scanRoutes);
router.use('/reports', reportRoutes);
router.use('/', dashboardRoutes);
router.use('/public', publicRoutes);

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
    });
});

module.exports = router;
