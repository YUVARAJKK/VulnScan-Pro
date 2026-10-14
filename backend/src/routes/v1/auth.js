const router = require('express').Router();
const auth = require('../../middleware/auth');
const {
    register,
    verifyEmail,
    resendVerification,
    login,
    verifyMfaLogin,
    setupMfa,
    enableMfa,
    disableMfa,
    getMe,
    updateProfile,
    changePassword,
    forgotPassword,
    resetPassword,
} = require('../../controllers/authController');

// Public auth routes
router.post('/register', register);
router.post('/verify-email', verifyEmail);
router.post('/resend-verification', resendVerification);
router.post('/login', login);
router.post('/mfa/verify', verifyMfaLogin);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// Authenticated routes
router.get('/me', auth, getMe);
router.put('/profile', auth, updateProfile);
router.put('/password', auth, changePassword);
router.post('/mfa/setup', auth, setupMfa);
router.post('/mfa/enable', auth, enableMfa);
router.post('/mfa/disable', auth, disableMfa);

module.exports = router;
