'use strict';

/**
 * Migration: Add new columns for the Python scanner engine
 * - New columns on vulnerabilities table
 * - New discovered_endpoints table
 * - New scan_metadata table
 */
module.exports = {
    async up(queryInterface, Sequelize) {
        // ═══ Add new columns to vulnerabilities table ═══
        await queryInterface.addColumn('vulnerabilities', 'confidence', {
            type: Sequelize.STRING(10),
            defaultValue: 'medium',
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'endpoint', {
            type: Sequelize.STRING(2048),
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'parameter', {
            type: Sequelize.STRING(500),
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'detected_by', {
            type: Sequelize.STRING(100),
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'mitre_technique', {
            type: Sequelize.STRING(20),
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'mitre_tactic', {
            type: Sequelize.STRING(50),
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'evidence', {
            type: Sequelize.JSONB,
            defaultValue: {},
            allowNull: true,
        });

        await queryInterface.addColumn('vulnerabilities', 'cvss_vector', {
            type: Sequelize.STRING(100),
            allowNull: true,
        });

        // ═══ Create discovered_endpoints table ═══
        await queryInterface.createTable('discovered_endpoints', {
            id: {
                type: Sequelize.UUID,
                defaultValue: Sequelize.UUIDV4,
                primaryKey: true,
            },
            scan_id: {
                type: Sequelize.UUID,
                allowNull: false,
                references: { model: 'scans', key: 'id' },
                onDelete: 'CASCADE',
            },
            url: {
                type: Sequelize.STRING(2048),
                allowNull: false,
            },
            method: {
                type: Sequelize.STRING(10),
                defaultValue: 'GET',
            },
            status_code: {
                type: Sequelize.INTEGER,
                allowNull: true,
            },
            content_type: {
                type: Sequelize.STRING(200),
                allowNull: true,
            },
            parameters: {
                type: Sequelize.JSONB,
                defaultValue: [],
            },
            discovered_by: {
                type: Sequelize.STRING(100),
                allowNull: true,
            },
            created_at: {
                type: Sequelize.DATE,
                defaultValue: Sequelize.NOW,
            },
        });

        // ═══ Create scan_metadata table ═══
        await queryInterface.createTable('scan_metadata', {
            id: {
                type: Sequelize.UUID,
                defaultValue: Sequelize.UUIDV4,
                primaryKey: true,
            },
            scan_id: {
                type: Sequelize.UUID,
                allowNull: false,
                unique: true,
                references: { model: 'scans', key: 'id' },
                onDelete: 'CASCADE',
            },
            health_score: {
                type: Sequelize.INTEGER,
                defaultValue: 100,
            },
            health_grade: {
                type: Sequelize.STRING(5),
                defaultValue: 'A+',
            },
            risk_score: {
                type: Sequelize.INTEGER,
                defaultValue: 0,
            },
            total_endpoints: {
                type: Sequelize.INTEGER,
                defaultValue: 0,
            },
            total_parameters: {
                type: Sequelize.INTEGER,
                defaultValue: 0,
            },
            scan_duration_ms: {
                type: Sequelize.INTEGER,
                allowNull: true,
            },
            scanner_version: {
                type: Sequelize.STRING(20),
                allowNull: true,
            },
            score_breakdown: {
                type: Sequelize.JSONB,
                defaultValue: {},
            },
            created_at: {
                type: Sequelize.DATE,
                defaultValue: Sequelize.NOW,
            },
        });

        // Add indexes
        await queryInterface.addIndex('discovered_endpoints', ['scan_id']);
        await queryInterface.addIndex('scan_metadata', ['scan_id']);
        await queryInterface.addIndex('vulnerabilities', ['detected_by']);
        await queryInterface.addIndex('vulnerabilities', ['mitre_technique']);
    },

    async down(queryInterface) {
        // Remove new columns from vulnerabilities
        await queryInterface.removeColumn('vulnerabilities', 'confidence');
        await queryInterface.removeColumn('vulnerabilities', 'endpoint');
        await queryInterface.removeColumn('vulnerabilities', 'parameter');
        await queryInterface.removeColumn('vulnerabilities', 'detected_by');
        await queryInterface.removeColumn('vulnerabilities', 'mitre_technique');
        await queryInterface.removeColumn('vulnerabilities', 'mitre_tactic');
        await queryInterface.removeColumn('vulnerabilities', 'evidence');
        await queryInterface.removeColumn('vulnerabilities', 'cvss_vector');

        // Drop new tables
        await queryInterface.dropTable('scan_metadata');
        await queryInterface.dropTable('discovered_endpoints');
    },
};
