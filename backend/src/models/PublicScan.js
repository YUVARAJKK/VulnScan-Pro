const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');
const crypto = require('crypto');

/**
 * PublicScan Model — stores scans initiated from the public landing page
 * No user account required. Access via secure tokenized link.
 */
const PublicScan = sequelize.define('PublicScan', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: { isEmail: true },
    },
    targetUrl: {
        type: DataTypes.STRING(2048),
        allowNull: false,
        field: 'target_url',
    },
    hostname: {
        type: DataTypes.STRING(500),
        allowNull: false,
    },
    accessToken: {
        type: DataTypes.STRING(128),
        allowNull: false,
        unique: true,
        field: 'access_token',
        defaultValue: () => crypto.randomBytes(48).toString('hex'),
    },
    tokenExpiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
        field: 'token_expires_at',
        defaultValue: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
    status: {
        type: DataTypes.ENUM('queued', 'running', 'completed', 'failed'),
        defaultValue: 'queued',
    },
    scannerTypes: {
        type: DataTypes.JSONB,
        defaultValue: ['custom'],
        field: 'scanner_types',
    },
    progress: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        validate: { min: 0, max: 100 },
    },
    startedAt: {
        type: DataTypes.DATE,
        field: 'started_at',
    },
    completedAt: {
        type: DataTypes.DATE,
        field: 'completed_at',
    },
    errorMessage: {
        type: DataTypes.TEXT,
        field: 'error_message',
    },
    totalVulnerabilities: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'total_vulnerabilities',
    },
    severityCounts: {
        type: DataTypes.JSONB,
        defaultValue: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        field: 'severity_counts',
    },
    riskScore: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'risk_score',
        comment: '0-100, higher = more risk',
    },
    healthScore: {
        type: DataTypes.INTEGER,
        defaultValue: 100,
        field: 'health_score',
        comment: '0-100, higher = healthier',
    },
    healthGrade: {
        type: DataTypes.STRING(5),
        defaultValue: 'A+',
        field: 'health_grade',
        comment: 'A+ / A / B / C / D / F',
    },
    ipAddress: {
        type: DataTypes.STRING(45),
        field: 'ip_address',
    },
    emailSent: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'email_sent',
    },
}, {
    tableName: 'public_scans',
    timestamps: true,
    underscored: true,
});

module.exports = PublicScan;
