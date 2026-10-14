const dns = require('dns').promises;
const net = require('net');
const logger = require('./logger');

/**
 * SSRF Protection — prevents scans against internal/private networks
 * Blocks: loopback, private RFC1918, link-local, multicast, IPv6 private ranges, etc.
 */

const BLOCKED_IP_RANGES = [
    // Loopback
    { start: '127.0.0.0', end: '127.255.255.255' },
    // Private (RFC 1918)
    { start: '10.0.0.0', end: '10.255.255.255' },
    { start: '172.16.0.0', end: '172.31.255.255' },
    { start: '192.168.0.0', end: '192.168.255.255' },
    // Link-local
    { start: '169.254.0.0', end: '169.254.255.255' },
    // CGNAT
    { start: '100.64.0.0', end: '100.127.255.255' },
    // Multicast
    { start: '224.0.0.0', end: '239.255.255.255' },
    // Broadcast
    { start: '255.255.255.255', end: '255.255.255.255' },
    // 0.0.0.0
    { start: '0.0.0.0', end: '0.255.255.255' },
];

/**
 * Blocked IPv6 ranges (as normalized 16-hex-char strings, see normalizeIPv6)
 * - ::/128               Unspecified
 * - ::1/128              Loopback
 * - fc00::/7             Unique Local Addresses (ULA)
 * - fe80::/10            Link-local
 * - ff00::/8             Multicast
 * - ::ffff:0:0/96        IPv4-mapped (validated separately against IPv4 ranges)
 */
const BLOCKED_IPV6_RANGES = [
    // Unspecified
    { start: '00000000000000000000000000000000', end: '00000000000000000000000000000000' },
    // Loopback ::1
    { start: '00000000000000000000000000000001', end: '00000000000000000000000000000001' },
    // Unique Local fc00::/7  (fc00 - fdff)
    { start: 'fc000000000000000000000000000000', end: 'fdffffffffffffffffffffffffffffff' },
    // Link-local fe80::/10 (fe80 - febf)
    { start: 'fe800000000000000000000000000000', end: 'febfffffffffffffffffffffffffffff' },
    // Multicast ff00::/8
    { start: 'ff000000000000000000000000000000', end: 'ffffffffffffffffffffffffffffffff' },
];

const BLOCKED_HOSTNAMES = [
    'localhost',
    'ip6-localhost',
    'ip6-loopback',
    '0.0.0.0',
    'metadata.google.internal',       // GCP metadata
    '169.254.169.254',                  // AWS/GCP/Azure metadata
    'metadata.internal',
];

/**
 * Convert an IPv4 address to a 32-bit integer for range checks
 */
function ipToLong(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Expand an IPv6 address into a canonical 32-hex-digit lowercase string.
 * Handles '::' compression and embedded IPv4 (e.g. ::ffff:192.168.1.1).
 * Returns null if the input is not a valid IPv6 address.
 */
function normalizeIPv6(ip) {
    if (!net.isIPv6(ip)) return null;

    let address = ip.toLowerCase();

    // Handle embedded IPv4 (e.g. "::ffff:192.168.1.1" → "::ffff:c0a8:0101")
    const v4Match = address.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4Match) {
        const v4Hex = v4Match.slice(1).map((octet) => {
            const num = parseInt(octet, 10);
            return num.toString(16).padStart(2, '0');
        }).join('');
        address = address.replace(/[0-9.]+$/, `${v4Hex.slice(0, 4)}:${v4Hex.slice(4)}`);
    }

    // Split on '::'
    const doubleColon = address.indexOf('::');
    let head = '';
    let tail = '';
    if (doubleColon !== -1) {
        head = address.slice(0, doubleColon);
        tail = address.slice(doubleColon + 2);
    } else {
        head = address;
    }

    const headParts = head ? head.split(':').filter(Boolean) : [];
    const tailParts = tail ? tail.split(':').filter(Boolean) : [];

    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;

    const groups = [...headParts];
    for (let i = 0; i < missing; i++) groups.push('0');
    groups.push(...tailParts);

    if (groups.length !== 8) return null;
    if (groups.some((g) => g.length > 4 || !/^[0-9a-f]+$/.test(g))) return null;

    return groups.map((g) => g.padStart(4, '0')).join('');
}

/**
 * Check if an IPv6 address falls within any blocked IPv6 range
 */
function isBlockedIPv6(ip) {
    // Strip zone-id suffix (e.g. fe80::1%eth0) before validation
    const cleanIp = ip.includes('%') ? ip.split('%')[0] : ip;
    const normalized = normalizeIPv6(cleanIp);
    if (!normalized) return false;

    // IPv4-mapped addresses (::ffff:0:0/96) — validate the embedded IPv4
    const v4Mapped = normalized.match(/^00000000000000000000ffff([0-9a-f]{8})$/);
    if (v4Mapped) {
        const v4 = v4Mapped[1];
        const ipv4 = `${parseInt(v4.slice(0, 2), 16)}.${parseInt(v4.slice(2, 4), 16)}.${parseInt(v4.slice(4, 6), 16)}.${parseInt(v4.slice(6, 8), 16)}`;
        return isBlockedIP(ipv4);
    }

    return BLOCKED_IPV6_RANGES.some(({ start, end }) => {
        return normalized >= start && normalized <= end;
    });
}

/**
 * Check if an IP address falls within any blocked range (IPv4 or IPv6)
 */
function isBlockedIP(ip) {
    // Strip IPv6 zone-id suffix (e.g. fe80::1%eth0) before validation
    const cleanIp = ip.includes('%') ? ip.split('%')[0] : ip;

    if (net.isIPv4(cleanIp)) {
        const ipLong = ipToLong(cleanIp);
        return BLOCKED_IP_RANGES.some(({ start, end }) => {
            const startLong = ipToLong(start);
            const endLong = ipToLong(end);
            return ipLong >= startLong && ipLong <= endLong;
        });
    }

    if (net.isIPv6(cleanIp)) {
        return isBlockedIPv6(cleanIp);
    }

    return false;
}

/**
 * Validate a target URL/hostname against SSRF attacks
 * @param {string} target - URL or hostname
 * @returns {Promise<{safe: boolean, hostname: string, ip: string, reason?: string}>}
 */
async function validateTarget(target) {
    try {
        // DEVELOPMENT/TEST ONLY: ALLOW_PRIVATE_SCAN_TARGETS=1 lets the platform
        // scan local lab targets (DVWA etc.). Never enable in production — it
        // disables the SSRF guards below.
        if (process.env.ALLOW_PRIVATE_SCAN_TARGETS === '1') {
            logger.warn('[SSRF] ALLOW_PRIVATE_SCAN_TARGETS enabled — guards bypassed (dev/test only)');
            return { safe: true, hostname: target, ip: null };
        }

        // Extract hostname from URL
        let hostname;
        try {
            const url = new URL(target);
            hostname = url.hostname;
        } catch {
            hostname = target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
        }

        // Strip brackets from IPv6 literals (e.g. [::1])
        if (hostname.startsWith('[') && hostname.endsWith(']')) {
            hostname = hostname.slice(1, -1);
        }

        // Check against blocked hostnames
        if (BLOCKED_HOSTNAMES.includes(hostname.toLowerCase())) {
            return { safe: false, hostname, ip: null, reason: `Hostname '${hostname}' is not allowed` };
        }

        // Direct IP check (IPv4 or IPv6)
        if (net.isIP(hostname)) {
            if (isBlockedIP(hostname)) {
                return { safe: false, hostname, ip: hostname, reason: 'Internal/private IP addresses are not allowed as scan targets' };
            }
            return { safe: true, hostname, ip: hostname };
        }

        // DNS resolution check — resolve hostname and verify IPs (A and AAAA records)
        let addresses = [];
        try {
            const dnsResults = await dns.lookup(hostname, { all: true, verbatim: true });
            addresses = dnsResults.map(r => r.address);
        } catch (dnsErr) {
            // If DNS lookup fails, try direct resolve4/resolve6 as fallback with custom public DNS if needed, or just fail naturally
            const servers = require('dns').getServers();
            if (servers.includes('127.0.0.1')) {
                require('dns').setServers(['8.8.8.8', '1.1.1.1']);
                try {
                    const v4 = await dns.resolve4(hostname);
                    addresses.push(...v4);
                } catch { /* no A records */ }
                try {
                    const v6 = await dns.resolve6(hostname);
                    addresses.push(...v6);
                } catch { /* no AAAA records */ }
                if (addresses.length === 0) throw dnsErr;
            } else {
                throw dnsErr;
            }
        }

        if (!addresses || addresses.length === 0) {
            return { safe: false, hostname, ip: null, reason: 'Could not resolve hostname to an IP address' };
        }

        for (const ip of addresses) {
            if (isBlockedIP(ip)) {
                logger.warn(`[SSRF] Blocked scan to ${hostname} — resolves to internal IP ${ip}`);
                return { safe: false, hostname, ip, reason: 'Target resolves to an internal/private IP address. This could be an SSRF attempt.' };
            }
        }

        return { safe: true, hostname, ip: addresses[0] };
    } catch (err) {
        logger.error(`[SSRF] Target validation error for '${target}':`, err.message);
        return { safe: false, hostname: target, ip: null, reason: `Cannot validate target: ${err.message}` };
    }
}

module.exports = { validateTarget, isBlockedIP, isBlockedIPv6, normalizeIPv6 };
