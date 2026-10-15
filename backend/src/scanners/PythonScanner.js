const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const config = require('../config');

/**
 * Locate the scanner_engine directory by walking up from this file until a
 * directory containing scanner_engine/main.py is found. Works in every layout:
 *   - local dev:  <repo>/backend/src/scanners -> <repo>/scanner_engine
 *   - worker image (backend copied to /app): /app/src/scanners -> /app/scanner_engine
 */
function resolveEngineDir() {
    let dir = path.resolve(__dirname);
    for (let i = 0; i < 6; i++) {
        const candidate = path.join(dir, 'scanner_engine', 'main.py');
        if (fs.existsSync(candidate)) {
            return path.join(dir, 'scanner_engine');
        }
        dir = path.dirname(dir);
    }
    return null;
}

/**
 * Python Scanner Bridge
 * =====================
 * Invokes the Python vulnerability scanner engine as a subprocess.
 * The Python scanner writes results directly to PostgreSQL.
 * This bridge monitors completion status and returns a summary.
 */
class PythonScanner {
    constructor() {
        this.name = 'custom';
        this.version = '3.0.0';
        this.timeout = 600000; // 10 minutes
    }

    async isAvailable() {
        try {
            const pythonPath = this._getPythonPath();
            return new Promise((resolve) => {
                const proc = spawn(pythonPath, ['--version'], { shell: false });
                proc.on('close', (code) => resolve(code === 0));
                proc.on('error', () => resolve(false));
                setTimeout(() => { proc.kill(); resolve(false); }, 5000);
            });
        } catch {
            return false;
        }
    }

    /**
     * Run the Python scanner against a target.
     * Returns a summary object (findings are written directly to DB by Python).
     */
    async run(target, options = {}) {
        const scanId = options.scanId;
        if (!scanId) {
            throw new Error('PythonScanner requires options.scanId');
        }

        // Assets store host-only targets (no scheme); the engine requires a
        // full http(s) URL, so normalise here once for every caller.
        if (target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
            // Explicit non-443 ports are almost always plain HTTP (dev lab
            // services), everything else defaults to HTTPS.
            const hostPort = (target.match(/:(\d+)$/) || [])[1];
            const scheme = hostPort && hostPort !== '443' ? 'http' : 'https';
            target = `${scheme}://${target}`;
        }

        const dbUrl = this._buildDbUrl();
        const pythonPath = this._getPythonPath();
        const engineDir = resolveEngineDir();
        if (!engineDir) {
            throw new Error('Could not locate scanner_engine/main.py — engine directory not found');
        }
        const scriptPath = path.join(engineDir, 'main.py');

        const args = [
            scriptPath,
            '--target', target,
            '--scan-id', scanId,
            '--db-url', dbUrl,
            '--scan-kind', options.scanKind || 'internal',
            '--timeout', String(options.timeout || 15),
            '--max-concurrent', String(options.maxConcurrent || 50),
        ];

        logger.info(`[PythonScanner] Invoking: ${pythonPath} ${args.join(' ')}`);

        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            let killed = false;

            const proc = spawn(pythonPath, args, {
                shell: false,
                cwd: engineDir,
                env: {
                    ...process.env,
                    PYTHONUNBUFFERED: '1',
                },
            });

            proc.stdout.on('data', (data) => { stdout += data.toString(); });
            proc.stderr.on('data', (data) => {
                stderr += data.toString();
                // Log Python stderr for debugging
                const lines = data.toString().split('\n').filter(l => l.trim());
                lines.forEach(line => logger.info(`[PythonScanner] ${line}`));
            });

            proc.on('close', (code) => {
                if (killed) return;

                if (code !== 0) {
                    logger.error(`[PythonScanner] Process exited with code ${code}`);
                    logger.error(`[PythonScanner] stderr: ${stderr.slice(-2000)}`);
                    reject(new Error(`Python scanner exited with code ${code}: ${stderr.slice(-500)}`));
                    return;
                }

                // Parse JSON summary from stdout
                try {
                    const lines = stdout.trim().split('\n');
                    const lastLine = lines[lines.length - 1];
                    const result = JSON.parse(lastLine);

                    if (!result.success) {
                        reject(new Error(result.error || 'Python scanner reported failure'));
                        return;
                    }

                    // Return a format compatible with the existing worker
                    // The actual findings are already in the DB — return summary
                    resolve({
                        summary: result,
                        // Return empty array since findings are written directly to DB
                        vulnerabilities: [],
                    });
                } catch (e) {
                    logger.error(`[PythonScanner] Failed to parse output: ${stdout.slice(-1000)}`);
                    reject(new Error(`Failed to parse Python scanner output: ${e.message}`));
                }
            });

            proc.on('error', (err) => {
                if (!killed) {
                    reject(new Error(`Failed to start Python scanner: ${err.message}`));
                }
            });

            // Timeout
            const timer = setTimeout(() => {
                killed = true;
                try { proc.kill('SIGTERM'); } catch {}
                setTimeout(() => {
                    try { proc.kill('SIGKILL'); } catch {}
                }, 5000);
                reject(new Error(`Python scanner timed out after ${this.timeout}ms`));
            }, this.timeout);

            proc.on('close', () => clearTimeout(timer));
        });
    }

    _getPythonPath() {
        // Try common Python locations
        return process.env.PYTHON_PATH || 'python3';
    }

    _buildDbUrl() {
        // Build PostgreSQL connection URL from config
        const db = config.db;
        return `postgresql://${db.user}:${db.password}@${db.host}:${db.port}/${db.name}`;
    }
}

module.exports = PythonScanner;
