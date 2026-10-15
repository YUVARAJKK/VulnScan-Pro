const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ScanPolicy = sequelize.define('ScanPolicy', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING(255),
        allowNull: false,
    },
    scannerType: {
        type: DataTypes.STRING(50),
        allowNull: false,
        field: 'scanner_type',
    },
    configuration: {
        type: DataTypes.JSONB,
        defaultValue: {},
    },
    description: {
        type: DataTypes.TEXT,
    },
}, {
    tableName: 'scan_policies',
    timestamps: true,
    underscored: true,
    updatedAt: false,
});

module.exports = ScanPolicy;
