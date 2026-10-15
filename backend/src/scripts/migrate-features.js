const { Sequelize } = require('sequelize');
const config = require('../config');

const sequelize = new Sequelize(config.db.name, config.db.user, config.db.password, {
    host: config.db.host,
    port: config.db.port,
    dialect: 'postgres',
    logging: console.log,
});

async function migrate() {
    try {
        await sequelize.authenticate();
        console.log('Connected to database');

        // Add new enum types
        const queries = [
            // Vulnerability status enum
            `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'enum_vulnerabilities_status') THEN CREATE TYPE enum_vulnerabilities_status AS ENUM ('open', 'resolved', 'ignored', 'false_positive'); END IF; END $$;`,
            // Scan schedule interval enum
            `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'enum_scans_schedule_interval') THEN CREATE TYPE enum_scans_schedule_interval AS ENUM ('daily', 'weekly', 'monthly'); END IF; END $$;`,
            // Vulnerability status column
            `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'open'`,
            // Vulnerability category column (was missing — authenticated scans failed to persist findings)
            `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS category VARCHAR(100)`,
            `UPDATE vulnerabilities SET category = 'other' WHERE category IS NULL`,
            // Vulnerability updated_at column
            `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE`,
            // Scan schedule columns
            `ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN DEFAULT false`,
            `ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_interval VARCHAR(20)`,
            `ALTER TABLE scans ADD COLUMN IF NOT EXISTS last_scheduled_at TIMESTAMP WITH TIME ZONE`,
            // Asset health columns
            `ALTER TABLE assets ADD COLUMN IF NOT EXISTS health_score INTEGER`,
            `ALTER TABLE assets ADD COLUMN IF NOT EXISTS health_grade VARCHAR(2)`,
            `ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP WITH TIME ZONE`,
            // Email verification columns
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255)`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_expires_at TIMESTAMP WITH TIME ZONE`,
            // Backfill: existing users were created before email verification existed —
            // keep them able to log in (only accounts created after this migration
            // go through the verification flow).
            `UPDATE users SET email_verified = true WHERE email_verified = false AND created_at < NOW() - INTERVAL '1 minute'`,
            // Password reset columns
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255)`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMP WITH TIME ZONE`,
            // Report format enum — allow JSON machine-readable exports
            `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'enum_reports_format' AND e.enumlabel = 'json') THEN ALTER TYPE enum_reports_format ADD VALUE 'json'; END IF; END $$;`,
        ];

        for (const sql of queries) {
            try {
                await sequelize.query(sql);
                console.log('OK:', sql.slice(0, 60) + '...');
            } catch (err) {
                console.log('SKIP:', err.message.slice(0, 80));
            }
        }

        console.log('\n✅ Migration complete!');
        process.exit(0);
    } catch (err) {
        console.error('❌ Migration error:', err.message);
        process.exit(1);
    }
}

migrate();
