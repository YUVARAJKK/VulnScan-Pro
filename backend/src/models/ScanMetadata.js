const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

/**
 * ScanMetadata — one-row-per-scan summary written by the Python scanner engine.
 * Mirrors the table the engine populates directly (health/risk score, endpoint
 * counts, duration, breakdown).
 */
const ScanMetadata = sequelize.define('ScanMetadata', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    scanId: {
        type: DataTypes.UUID,
        allowNull: false,
        unique: true,
        field: 'scan_id',
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
    },
    riskScore: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'risk_score',
        comment: '0-100, higher = more risk',
    },
    totalEndpoints: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'total_endpoints',
    },
    totalParameters: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'total_parameters',
    },
    scanDurationMs: {
        type: DataTypes.INTEGER,
        field: 'scan_duration_ms',
    },
    scannerVersion: {
        type: DataTypes.STRING(20),
        field: 'scanner_version',
    },
    scoreBreakdown: {
        type: DataTypes.JSONB,
        defaultValue: {},
        field: 'score_breakdown',
    },
    createdAt: {
        type: DataTypes.DATE,
        field: 'created_at',
    },
}, {
    tableName: 'scan_metadata',
    timestamps: false,
    underscored: true,
});

module.exports = ScanMetadata;
