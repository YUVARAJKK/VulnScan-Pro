const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Report = sequelize.define('Report', {
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
    scanId: {
        type: DataTypes.UUID,
        allowNull: false,
        field: 'scan_id',
    },
    title: {
        type: DataTypes.STRING(255),
        allowNull: false,
    },
    format: {
        type: DataTypes.ENUM('pdf', 'html', 'json'),
        defaultValue: 'pdf',
    },
    template: {
        type: DataTypes.STRING(50),
        allowNull: true,
        defaultValue: 'technical',
    },
    version: {
        type: DataTypes.STRING(20),
        allowNull: true,
        defaultValue: '1.0',
    },
    status: {
        type: DataTypes.ENUM('generating', 'completed', 'failed'),
        defaultValue: 'generating',
    },
    filePath: {
        type: DataTypes.STRING(500),
        field: 'file_path',
    },
    fileSize: {
        type: DataTypes.INTEGER,
        field: 'file_size',
    },
    errorMessage: {
        type: DataTypes.TEXT,
        field: 'error_message',
        allowNull: true,
    },
}, {
    tableName: 'reports',
    timestamps: true,
    underscored: true,
    updatedAt: false,
});

module.exports = Report;
