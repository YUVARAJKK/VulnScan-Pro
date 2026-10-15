const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

/**
 * DiscoveredEndpoint — endpoints/forms discovered by the Python engine during
 * a scan (crawler, forms, sitemap). Written by the engine, read by the API.
 */
const DiscoveredEndpoint = sequelize.define('DiscoveredEndpoint', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    scanId: {
        type: DataTypes.UUID,
        allowNull: false,
        field: 'scan_id',
    },
    url: {
        type: DataTypes.STRING(2048),
        allowNull: false,
    },
    method: {
        type: DataTypes.STRING(10),
        defaultValue: 'GET',
    },
    statusCode: {
        type: DataTypes.INTEGER,
        field: 'status_code',
    },
    contentType: {
        type: DataTypes.STRING(200),
        field: 'content_type',
    },
    parameters: {
        type: DataTypes.JSONB,
        defaultValue: [],
    },
    discoveredBy: {
        type: DataTypes.STRING(100),
        field: 'discovered_by',
    },
    createdAt: {
        type: DataTypes.DATE,
        field: 'created_at',
    },
}, {
    tableName: 'discovered_endpoints',
    timestamps: false,
    underscored: true,
});

module.exports = DiscoveredEndpoint;
