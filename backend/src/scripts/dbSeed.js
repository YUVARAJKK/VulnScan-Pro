/**
 * Database Seed Script
 * Creates sample data for development and testing
 * Usage: node src/scripts/dbSeed.js
 */
require('dotenv').config();
const bcrypt = require('bcryptjs');
const sequelize = require('../config/database');
const { User, Asset, ScanPolicy } = require('../models');

async function seedDatabase() {
    try {
        await sequelize.authenticate();
        console.log('✅ Database connected');

        // Create admin user
        const adminPassword = await bcrypt.hash('Admin@123', 12);
        const [admin] = await User.findOrCreate({
            where: { email: 'admin@vulnscan.com' },
            defaults: {
                firstName: 'System',
                lastName: 'Admin',
                email: 'admin@vulnscan.com',
                passwordHash: adminPassword,
                role: 'admin',
                emailVerified: true,
            },
        });
        console.log(`✅ Admin user: admin@vulnscan.com / Admin@123`);

        // Create analyst user
        const analystPassword = await bcrypt.hash('Analyst@123', 12);
        const [analyst] = await User.findOrCreate({
            where: { email: 'analyst@vulnscan.com' },
            defaults: {
                firstName: 'Security',
                lastName: 'Analyst',
                email: 'analyst@vulnscan.com',
                passwordHash: analystPassword,
                role: 'analyst',
                emailVerified: true,
            },
        });
        console.log(`✅ Analyst user: analyst@vulnscan.com / Analyst@123`);

        // Create sample assets with REAL URLs
        const sampleAssets = [
            { name: 'Google DNS', type: 'ip', target: '8.8.8.8', description: 'Google Public DNS Server' },
            { name: 'Cloudflare DNS', type: 'ip', target: '1.1.1.1', description: 'Cloudflare Public DNS' },
            { name: 'Example.com', type: 'domain', target: 'example.com', description: 'IANA Example Domain' },
            { name: 'Scanme Nmap', type: 'domain', target: 'scanme.nmap.org', description: 'Official Nmap test target (authorized for scanning)' },
            { name: 'TestPHP Vulnweb', type: 'domain', target: 'testphp.vulnweb.com', description: 'Acunetix test site for web vuln scanning' },
            { name: 'OWASP Juice Shop', type: 'domain', target: 'juice-shop.herokuapp.com', description: 'OWASP vulnerable web application' },
            { name: 'HackTheBox', type: 'domain', target: 'hackthebox.com', description: 'HackTheBox platform' },
            { name: 'Local Network', type: 'subnet', target: '192.168.1.0/24', description: 'Local network subnet' },
        ];

        for (const asset of sampleAssets) {
            await Asset.findOrCreate({
                where: { target: asset.target, userId: admin.id },
                defaults: { ...asset, userId: admin.id },
            });
        }
        console.log('✅ Sample assets created (real scannable targets)');

        // Create scan policies
        const policies = [
            { name: 'Quick Port Scan', scannerType: 'nmap', configuration: { ports: '1-1000', intensity: 'quick' }, description: 'Fast scan of top 1000 ports' },
            { name: 'Full Port Scan', scannerType: 'nmap', configuration: { ports: '1-65535', intensity: 'thorough' }, description: 'Comprehensive scan of all ports' },
            { name: 'Full Web Assessment', scannerType: 'custom', configuration: {}, description: 'VulnScan Pro custom Python engine scan' },
            { name: 'WordPress Scan', scannerType: 'wpscan', configuration: { enumeratePlugins: true }, description: 'WordPress vulnerability scan' },
            { name: 'Custom Security Check', scannerType: 'custom', configuration: {}, description: 'Built-in security checks (headers, SSL, DNS, ports)' },
        ];

        for (const policy of policies) {
            await ScanPolicy.findOrCreate({
                where: { name: policy.name },
                defaults: policy,
            });
        }
        console.log('✅ Scan policies created');

        console.log('\n🎉 Database seeded successfully!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Seed failed:', error);
        process.exit(1);
    }
}

seedDatabase();
