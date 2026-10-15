const PythonScanner = require('./PythonScanner');

/**
 * Scanner Plugin Registry
 * Single unified scanner — Python vulnerability scanning engine.
 * All third-party scanner dependencies have been removed.
 */
const scanners = {
    custom: new PythonScanner(),
};

/**
 * Get scanner by type
 */
function getScanner(type) {
    // Map legacy scanner types to the unified custom scanner
    const normalizedType = type === 'full' ? 'custom' : type;
    const scanner = scanners[normalizedType];
    if (!scanner) throw new Error(`Unknown scanner type: ${type}. Only 'custom' is supported.`);
    return scanner;
}

/**
 * Get all available scanners
 */
async function getAvailableScanners() {
    const available = [];
    for (const [type, scanner] of Object.entries(scanners)) {
        const isAvailable = await scanner.isAvailable();
        available.push({ type, name: scanner.name, version: scanner.version, available: isAvailable });
    }
    return available;
}

module.exports = { scanners, getScanner, getAvailableScanners };
