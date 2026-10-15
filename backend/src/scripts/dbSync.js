/**
 * Database Sync Script
 * Creates all tables based on Sequelize models
 * Usage: node src/scripts/dbSync.js
 */
require('dotenv').config();
const sequelize = require('../config/database');
require('../models'); // Register all models and associations

async function syncDatabase() {
    try {
        await sequelize.authenticate();
        console.log('✅ Database connected');

        // Use force: true to drop and recreate all tables (DEV ONLY)
        // Use alter: true to modify existing tables
        const force = process.argv.includes('--force');

        await sequelize.sync({ force, alter: !force });
        console.log(`✅ Database synced (${force ? 'force' : 'alter'} mode)`);

        process.exit(0);
    } catch (error) {
        console.error('❌ Database sync failed:', error);
        process.exit(1);
    }
}

syncDatabase();
