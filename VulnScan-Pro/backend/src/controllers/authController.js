const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Joi = require('joi');
const config = require('../config');
const { User } = require('../models');
const { createAuditLog } = require('../middleware/audit');
const emailService = require('../utils/emailService');
const logger = require('../utils/logger');

// ─── Validation Schemas ───
const registerSchema = Joi.object({
    firstName: Joi.string().min(1).max(100).required(),
    lastName: Joi.string().min(1).max(100).required(),
    email: Joi.string().email({ tlds: false }).required(),
    password: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .required()
        .messages({
            'string.pattern.base':
                'Password must contain uppercase, lowercase, number, and special character',
        }),
});

const loginSchema = Joi.object({
    email: Joi.string().email({ tlds: false }).required(),
    password: Joi.string().required(),
    mfaCode: Joi.string().pattern(/^\d{6}$/).allow('', null),
});

const passwordSchema = Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .required()
    .messages({
        'string.pattern.base':
            'Password must contain uppercase, lowercase, number, and special character',
    });

// ─── Helpers ───

const generateToken = (user) => {
    return jwt.sign(
        { userId: user.id, role: user.role },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
    );
};

/** Short-lived token that proves password login succeeded; exchanged for a full JWT after MFA code */
const generateMfaToken = (user) => {
    return jwt.sign(
        { userId: user.id, purpose: 'mfa' },
        config.jwt.secret,
        { expiresIn: '5m' }
    );
};

/** Random token used for email verification / password reset links */
const generateEmailToken = () => crypto.randomBytes(48).toString('hex');

const publicUser = (user) => ({
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
    mfaEnabled: !!user.mfaEnabled,
    emailVerified: !!user.emailVerified,
    createdAt: user.createdAt,
});

const verifyTOTP = (code, secret) => {
    if (!secret || !/^\d{6}$/.test(String(code || ''))) return false;
    try {
        const { authenticator } = require('otplib');
        // Allow ±1 time step (30s) to accommodate clock drift
        authenticator.options = { ...authenticator.options, window: 1 };
        return authenticator.verify({ token: String(code), secret });
    } catch (err) {
        logger.warn('TOTP verification error:', err.message);
        return false;
    }
};

const findUserByEmail = async (email) => {
    return User.findOne({ where: { email: email.toLowerCase() } });
};

// ─── Controllers ───

/**
 * POST /auth/register
 * Creates an account and sends an email verification link. Login is blocked
 * until the email is verified.
 */
const register = async (req, res, next) => {
    try {
        const { error, value } = registerSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const existingUser = await findUserByEmail(value.email);
        if (existingUser) {
            return res.status(409).json({ success: false, error: { code: 'CONFLICT', message: 'Email already registered' } });
        }

        const passwordHash = await bcrypt.hash(value.password, 12);
        const verificationToken = generateEmailToken();

        // In local/dev mode (no SMTP configured) verification emails can never
        // be delivered, so auto-verify the account instead of locking the user
        // out. With SMTP configured, the standard verification flow applies.
        const autoVerify = !emailService.isSmtpConfigured;

        const user = await User.create({
            firstName: value.firstName,
            lastName: value.lastName,
            email: value.email.toLowerCase(),
            passwordHash,
            role: 'analyst', // every registered user can create scans, view results and download reports
            emailVerified: autoVerify,
            verificationToken: autoVerify ? null : verificationToken,
            verificationTokenExpiresAt: autoVerify ? null : new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h
        });

        await createAuditLog(user.id, 'user.register', 'user', user.id, {}, req.ip);

        // Send verification email (best-effort — never blocks registration)
        if (!autoVerify) {
            try {
                await emailService.sendVerificationEmail(user.email, {
                    name: `${user.firstName} ${user.lastName}`,
                    token: verificationToken,
                });
            } catch (emailErr) {
                logger.warn('Verification email failed to send:', emailErr.message);
            }
        } else {
            logger.info(`SMTP not configured — account ${user.email} auto-verified (dev mode)`);
        }

        res.status(201).json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                role: user.role,
                emailVerified: autoVerify,
            },
            message: autoVerify
                ? 'Registration successful! You can log in immediately.'
                : 'Registration successful! A verification email has been sent. Please verify your email before logging in.',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/verify-email
 * Verifies a user's email using the token from the verification link.
 */
const verifyEmail = async (req, res, next) => {
    try {
        const schema = Joi.object({
            token: Joi.string().min(32).required(),
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await User.findOne({ where: { verificationToken: value.token } });
        if (!user) {
            return res.status(400).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Verification link is invalid or has already been used' } });
        }

        if (user.verificationTokenExpiresAt && new Date() > new Date(user.verificationTokenExpiresAt)) {
            return res.status(400).json({ success: false, error: { code: 'TOKEN_EXPIRED', message: 'Verification link has expired. Please request a new one.' } });
        }

        await user.update({
            emailVerified: true,
            verificationToken: null,
            verificationTokenExpiresAt: null,
        });

        await createAuditLog(user.id, 'user.verify_email', 'user', user.id, {}, req.ip);

        res.json({ success: true, message: 'Email verified successfully! You can now log in.' });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/resend-verification
 * Sends a fresh verification link to the given email.
 */
const resendVerification = async (req, res, next) => {
    try {
        const schema = Joi.object({
            email: Joi.string().email({ tlds: false }).required(),
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await findUserByEmail(value.email);
        // Always respond identically to avoid user enumeration
        if (!user) {
            return res.json({ success: true, message: 'If that email is registered, a new verification link has been sent.' });
        }
        if (user.emailVerified) {
            return res.json({ success: true, message: 'This email is already verified. You can log in.' });
        }

        const verificationToken = generateEmailToken();
        await user.update({
            verificationToken,
            verificationTokenExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });

        try {
            await emailService.sendVerificationEmail(user.email, {
                name: `${user.firstName} ${user.lastName}`,
                token: verificationToken,
            });
        } catch (emailErr) {
            logger.warn('Resend verification email failed:', emailErr.message);
        }

        res.json({ success: true, message: 'A new verification link has been sent to your email.' });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/login
 * Authenticates and returns a JWT. Enforces email verification and,
 * when MFA is enabled, issues a short-lived mfa token instead of a full JWT.
 */
const login = async (req, res, next) => {
    try {
        const { error, value } = loginSchema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await findUserByEmail(value.email);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
        }

        const isValidPassword = await bcrypt.compare(value.password, user.passwordHash);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
        }

        // Email verification gate
        if (!user.emailVerified) {
            return res.status(403).json({
                success: false,
                error: {
                    code: 'EMAIL_NOT_VERIFIED',
                    message: 'Please verify your email address before logging in. Check your inbox or request a new verification link.',
                },
            });
        }

        // MFA step
        if (user.mfaEnabled) {
            // Allow completing MFA via the same login call if a code was supplied
            if (value.mfaCode) {
                if (!verifyTOTP(value.mfaCode, user.mfaSecret)) {
                    return res.status(401).json({ success: false, error: { code: 'INVALID_MFA_CODE', message: 'Invalid authentication code' } });
                }
            } else {
                const mfaToken = generateMfaToken(user);
                return res.json({
                    success: true,
                    data: { mfaRequired: true, mfaToken },
                    message: 'Two-factor authentication required',
                });
            }
        }

        const token = generateToken(user);
        await createAuditLog(user.id, 'user.login', 'user', user.id, {}, req.ip);

        res.json({
            success: true,
            data: { token, user: publicUser(user) },
        });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/mfa/verify
 * Exchanges a short-lived mfa token + TOTP code for a full JWT.
 */
const verifyMfaLogin = async (req, res, next) => {
    try {
        const schema = Joi.object({
            mfaToken: Joi.string().required(),
            code: Joi.string().pattern(/^\d{6}$/).required(),
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        let decoded;
        try {
            decoded = jwt.verify(value.mfaToken, config.jwt.secret);
        } catch {
            return res.status(401).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Session expired. Please log in again.' } });
        }

        if (decoded.purpose !== 'mfa') {
            return res.status(401).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Invalid token' } });
        }

        const user = await User.findByPk(decoded.userId);
        if (!user || !user.isActive || !user.mfaEnabled) {
            return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Unable to verify two-factor authentication' } });
        }

        if (!verifyTOTP(value.code, user.mfaSecret)) {
            return res.status(401).json({ success: false, error: { code: 'INVALID_MFA_CODE', message: 'Invalid authentication code' } });
        }

        const token = generateToken(user);
        await createAuditLog(user.id, 'user.login', 'user', user.id, { mfa: true }, req.ip);

        res.json({ success: true, data: { token, user: publicUser(user) } });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/mfa/setup
 * Generates a new TOTP secret and provisioning URI. The secret is stored but
 * MFA stays disabled until the first code is verified via /auth/mfa/enable.
 */
const setupMfa = async (req, res, next) => {
    try {
        const { generateSecret, generateURI } = require('otplib');
        const secret = generateSecret();
        const otpauthUrl = generateURI({
            secret,
            label: req.user.email,
            issuer: 'VulnScan Pro',
        });

        await req.user.update({ mfaSecret: secret, mfaEnabled: false });

        await createAuditLog(req.user.id, 'user.mfa_setup', 'user', req.user.id, {}, req.ip);

        res.json({
            success: true,
            data: { secret, otpauthUrl },
            message: 'Scan the QR code or enter the secret in your authenticator app, then confirm with a code.',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/mfa/enable
 * Verifies the first TOTP code and activates MFA for the account.
 */
const enableMfa = async (req, res, next) => {
    try {
        const schema = Joi.object({ code: Joi.string().pattern(/^\d{6}$/).required() });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: 'Enter a valid 6-digit code' } });

        // Re-fetch full user: auth middleware excludes mfaSecret from req.user
        const user = await User.findByPk(req.user.id);
        if (!verifyTOTP(value.code, user.mfaSecret)) {
            return res.status(400).json({ success: false, error: { code: 'INVALID_MFA_CODE', message: 'Invalid code. Check that the time on your device is correct.' } });
        }

        await user.update({ mfaEnabled: true });
        await createAuditLog(user.id, 'user.mfa_enable', 'user', user.id, {}, req.ip);

        res.json({ success: true, message: 'Two-factor authentication enabled' });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/mfa/disable
 * Disables MFA after verifying the current TOTP code.
 */
const disableMfa = async (req, res, next) => {
    try {
        const schema = Joi.object({ code: Joi.string().pattern(/^\d{6}$/).required() });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: 'Enter a valid 6-digit code' } });

        // Re-fetch full user: auth middleware excludes mfaSecret from req.user
        const user = await User.findByPk(req.user.id);
        if (!verifyTOTP(value.code, user.mfaSecret)) {
            return res.status(400).json({ success: false, error: { code: 'INVALID_MFA_CODE', message: 'Invalid code. Check that the time on your device is correct.' } });
        }

        await user.update({ mfaEnabled: false, mfaSecret: null });
        await createAuditLog(user.id, 'user.mfa_disable', 'user', user.id, {}, req.ip);

        res.json({ success: true, message: 'Two-factor authentication disabled' });
    } catch (err) {
        next(err);
    }
};

/**
 * GET /auth/me
 */
const getMe = async (req, res) => {
    res.json({
        success: true,
        data: publicUser(req.user),
    });
};

/**
 * PUT /auth/profile
 */
const updateProfile = async (req, res, next) => {
    try {
        const schema = Joi.object({
            firstName: Joi.string().min(1).max(100),
            lastName: Joi.string().min(1).max(100),
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        await req.user.update(value);

        res.json({
            success: true,
            data: { id: req.user.id, firstName: req.user.firstName, lastName: req.user.lastName },
            message: 'Profile updated',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * PUT /auth/password
 */
const changePassword = async (req, res, next) => {
    try {
        const schema = Joi.object({
            currentPassword: Joi.string().required(),
            newPassword: passwordSchema,
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await User.findByPk(req.user.id);
        const isValid = await bcrypt.compare(value.currentPassword, user.passwordHash);
        if (!isValid) {
            return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Current password is incorrect' } });
        }

        user.passwordHash = await bcrypt.hash(value.newPassword, 12);
        await user.save();

        await createAuditLog(user.id, 'user.password_change', 'user', user.id, {}, req.ip);

        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/forgot-password
 * Emails a password reset link if the account exists. Always returns the same
 * response to avoid user enumeration.
 */
const forgotPassword = async (req, res, next) => {
    try {
        const schema = Joi.object({
            email: Joi.string().email({ tlds: false }).required(),
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await findUserByEmail(value.email);
        if (user && user.isActive) {
            const resetToken = generateEmailToken();
            await user.update({
                passwordResetToken: resetToken,
                passwordResetExpiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1h
            });

            try {
                await emailService.sendPasswordResetEmail(user.email, {
                    name: `${user.firstName} ${user.lastName}`,
                    token: resetToken,
                });
            } catch (emailErr) {
                logger.warn('Password reset email failed:', emailErr.message);
            }
        }

        res.json({
            success: true,
            message: 'If an account exists for that email, a password reset link has been sent.',
        });
    } catch (err) {
        next(err);
    }
};

/**
 * POST /auth/reset-password
 * Sets a new password using a valid reset token.
 */
const resetPassword = async (req, res, next) => {
    try {
        const schema = Joi.object({
            token: Joi.string().min(32).required(),
            newPassword: passwordSchema,
        });
        const { error, value } = schema.validate(req.body);
        if (error) return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });

        const user = await User.findOne({ where: { passwordResetToken: value.token } });
        if (!user) {
            return res.status(400).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Reset link is invalid or has already been used' } });
        }
        if (user.passwordResetExpiresAt && new Date() > new Date(user.passwordResetExpiresAt)) {
            return res.status(400).json({ success: false, error: { code: 'TOKEN_EXPIRED', message: 'Reset link has expired. Please request a new one.' } });
        }

        user.passwordHash = await bcrypt.hash(value.newPassword, 12);
        user.passwordResetToken = null;
        user.passwordResetExpiresAt = null;
        await user.save();

        await createAuditLog(user.id, 'user.password_reset', 'user', user.id, {}, req.ip);

        res.json({ success: true, message: 'Password reset successfully. You can now log in.' });
    } catch (err) {
        next(err);
    }
};

module.exports = {
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
};
