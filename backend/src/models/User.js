const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    firstName: {
        type: DataTypes.STRING(100),
        allowNull: false,
        field: 'first_name',
    },
    lastName: {
        type: DataTypes.STRING(100),
        allowNull: false,
        field: 'last_name',
    },
    email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true,
        validate: { isEmail: true },
    },
    passwordHash: {
        type: DataTypes.STRING(255),
        allowNull: false,
        field: 'password_hash',
    },
    role: {
        type: DataTypes.ENUM('admin', 'analyst', 'viewer'),
        defaultValue: 'viewer',
    },
    mfaEnabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'mfa_enabled',
    },
    mfaSecret: {
        type: DataTypes.STRING(255),
        field: 'mfa_secret',
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_active',
    },
    emailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'email_verified',
    },
    verificationToken: {
        type: DataTypes.STRING(255),
        field: 'verification_token',
    },
    verificationTokenExpiresAt: {
        type: DataTypes.DATE,
        field: 'verification_token_expires_at',
    },
    passwordResetToken: {
        type: DataTypes.STRING(255),
        field: 'password_reset_token',
    },
    passwordResetExpiresAt: {
        type: DataTypes.DATE,
        field: 'password_reset_expires_at',
    },
}, {
    tableName: 'users',
    timestamps: true,
    underscored: true,
});

module.exports = User;
