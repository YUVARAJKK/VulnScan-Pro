const User = require('./User');
const Asset = require('./Asset');
const Scan = require('./Scan');
const ScanPolicy = require('./ScanPolicy');
const Vulnerability = require('./Vulnerability');
const Report = require('./Report');
const AuditLog = require('./AuditLog');
const PublicScan = require('./PublicScan');
const PublicVulnerability = require('./PublicVulnerability');
const ScanMetadata = require('./ScanMetadata');
const DiscoveredEndpoint = require('./DiscoveredEndpoint');

// ─── Associations ───

// User → Assets
User.hasMany(Asset, { foreignKey: 'userId', as: 'assets' });
Asset.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// User → Scans
User.hasMany(Scan, { foreignKey: 'userId', as: 'scans' });
Scan.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Asset → Scans
Asset.hasMany(Scan, { foreignKey: 'assetId', as: 'scans' });
Scan.belongsTo(Asset, { foreignKey: 'assetId', as: 'asset' });

// ScanPolicy → Scans
ScanPolicy.hasMany(Scan, { foreignKey: 'policyId', as: 'scans' });
Scan.belongsTo(ScanPolicy, { foreignKey: 'policyId', as: 'policy' });

// Scan → Vulnerabilities
Scan.hasMany(Vulnerability, { foreignKey: 'scanId', as: 'vulnerabilities' });
Vulnerability.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

// User → Reports
User.hasMany(Report, { foreignKey: 'userId', as: 'reports' });
Report.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Scan → Reports
Scan.hasMany(Report, { foreignKey: 'scanId', as: 'reports' });
Report.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

// User → AuditLogs
User.hasMany(AuditLog, { foreignKey: 'userId', as: 'auditLogs' });
AuditLog.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// PublicScan → PublicVulnerabilities
PublicScan.hasMany(PublicVulnerability, { foreignKey: 'publicScanId', as: 'vulnerabilities' });
PublicVulnerability.belongsTo(PublicScan, { foreignKey: 'publicScanId', as: 'publicScan' });

// Scan → ScanMetadata (1:1) & Scan → DiscoveredEndpoints (1:N)
Scan.hasOne(ScanMetadata, { foreignKey: 'scanId', as: 'metadata' });
ScanMetadata.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

Scan.hasMany(DiscoveredEndpoint, { foreignKey: 'scanId', as: 'endpoints' });
DiscoveredEndpoint.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

module.exports = {
    User,
    Asset,
    Scan,
    ScanPolicy,
    Vulnerability,
    Report,
    AuditLog,
    PublicScan,
    PublicVulnerability,
    ScanMetadata,
    DiscoveredEndpoint,
};
