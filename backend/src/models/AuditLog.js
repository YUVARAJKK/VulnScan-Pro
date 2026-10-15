const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const AuditLog = sequelize.define('AuditLog', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    userId: {
        type: DataTypes.UUID,
        field: 'user_id',
    },
    action: {
        type: DataTypes.STRING(100),
        allowNull: false,
    },
    resourceType: {
        type: DataTypes.STRING(50),
        field: 'resource_type',
    },
    resourceId: {
        type: DataTypes.UUID,
        field: 'resource_id',
    },
    details: {
        type: DataTypes.JSONB,
        defaultValue: {},
    },
    ipAddress: {
        type: DataTypes.STRING(45),
        field: 'ip_address',
    },
}, {
    tableName: 'audit_logs',
    timestamps: true,
    underscored: true,
    updatedAt: false,
});

module.exports = AuditLog;
