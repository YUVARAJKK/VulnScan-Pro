const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Asset = sequelize.define('Asset', {
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
    name: {
        type: DataTypes.STRING(255),
        allowNull: false,
    },
    type: {
        type: DataTypes.ENUM('ip', 'domain', 'subnet'),
        allowNull: false,
    },
    target: {
        type: DataTypes.STRING(500),
        allowNull: false,
    },
    description: {
        type: DataTypes.TEXT,
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_active',
    },
    healthScore: {
        type: DataTypes.INTEGER,
        defaultValue: null,
        field: 'health_score',
        validate: { min: 0, max: 100 },
    },
    healthGrade: {
        type: DataTypes.STRING(2),
        defaultValue: null,
        field: 'health_grade',
    },
    lastScanAt: {
        type: DataTypes.DATE,
        field: 'last_scan_at',
    },
}, {
    tableName: 'assets',
    timestamps: true,
    underscored: true,
});

module.exports = Asset;
