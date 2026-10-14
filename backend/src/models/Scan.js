const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Scan = sequelize.define('Scan', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        field: 'user_id',
    },
    assetId: {
        type: DataTypes.UUID,
        allowNull: false,
        field: 'asset_id',
    },
    policyId: {
        type: DataTypes.UUID,
        field: 'policy_id',
    },
    scannerType: {
        type: DataTypes.STRING(50),
        allowNull: false,
        field: 'scanner_type',
    },
    status: {
        type: DataTypes.ENUM('queued', 'running', 'completed', 'failed', 'cancelled'),
        defaultValue: 'queued',
    },
    progress: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        validate: { min: 0, max: 100 },
        comment: '0-100 scan progress reported by the engine (0 for non-python scanners)',
    },
    parameters: {
        type: DataTypes.JSONB,
        defaultValue: {},
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
    cronExpression: {
        type: DataTypes.STRING(100),
        field: 'cron_expression',
    },
    scheduleEnabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'schedule_enabled',
    },
    scheduleInterval: {
        type: DataTypes.ENUM('daily', 'weekly', 'monthly'),
        field: 'schedule_interval',
    },
    lastScheduledAt: {
        type: DataTypes.DATE,
        field: 'last_scheduled_at',
    },
}, {
    tableName: 'scans',
    timestamps: true,
    underscored: true,
});

module.exports = Scan;
