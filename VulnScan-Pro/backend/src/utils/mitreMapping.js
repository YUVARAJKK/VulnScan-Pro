/**
 * MITRE ATT&CK® Mapping Utility
 * ---------------------------------------------
 * Correlates detected vulnerabilities to MITRE ATT&CK® techniques and tactics
 * so reports can include an adversary-focused attack map per finding and at
 * the assessment level.
 *
 * NOTE: The frontend (PublicReportPage.jsx) mirrors this library as a fallback
 * for native-dev deployments. Keep MITRE_LIB / MITRE_CAT / MITRE_KEYWORDS in
 * sync with TECHNIQUE_LIBRARY / CATEGORY_TECHNIQUES / KEYWORD_OVERRIDES here.
 *
 * Reference: https://attack.mitre.org
 */

// ─── Technique Library: id -> [name, tactic] ─────────────────────────────────
const TECHNIQUE_LIBRARY = {
    T1595: ['Active Scanning', 'Reconnaissance'],
    T1590: ['Gather Victim Network Information', 'Reconnaissance'],
    T1592: ['Gather Victim Host Information', 'Reconnaissance'],
    T1190: ['Exploit Public-Facing Application', 'Initial Access'],
    T1189: ['Drive-by Compromise', 'Initial Access'],
    T1195: ['Supply Chain Compromise', 'Initial Access'],
    T1078: ['Valid Accounts', 'Defense Evasion'],
    T1110: ['Brute Force', 'Credential Access'],
    T1059: ['Command and Scripting Interpreter', 'Execution'],
    'T1059.007': ['JavaScript / JScript', 'Execution'],
    T1068: ['Exploitation for Privilege Escalation', 'Privilege Escalation'],
    T1548: ['Abuse Elevation Control Mechanism', 'Privilege Escalation'],
    T1505: ['Server Software Component', 'Persistence'],
    T1136: ['Create Account', 'Persistence'],
    T1543: ['Create or Modify System Process', 'Persistence'],
    T1562: ['Impair Defenses', 'Defense Evasion'],
    T1070: ['Indicator Removal', 'Defense Evasion'],
    T1027: ['Obfuscated Files or Information', 'Defense Evasion'],
    T1040: ['Network Sniffing', 'Credential Access'],
    T1552: ['Unsecured Credentials', 'Credential Access'],
    T1557: ['Adversary-in-the-Middle', 'Credential Access'],
    T1539: ['Steal Web Session Cookie', 'Credential Access'],
    T1185: ['Browser Session Hijacking', 'Collection'],
    T1005: ['Data from Local System', 'Collection'],
    T1046: ['Network Service Discovery', 'Discovery'],
    T1135: ['Network Share Discovery', 'Discovery'],
    T1082: ['System Information Discovery', 'Discovery'],
    T1210: ['Exploitation of Remote Services', 'Lateral Movement'],
    T1021: ['Remote Services', 'Lateral Movement'],
    T1071: ['Application Layer Protocol', 'Command and Control'],
    T1568: ['Dynamic Resolution', 'Command and Control'],
    T1105: ['Ingress Tool Transfer', 'Command and Control'],
    T1041: ['Exfiltration Over C2 Channel', 'Exfiltration'],
    T1567: ['Exfiltration Over Web Service', 'Exfiltration'],
    T1485: ['Data Destruction', 'Impact'],
    T1498: ['Network Denial of Service', 'Impact'],
    T1499: ['Endpoint Denial of Service', 'Impact'],
    T1553: ['Subvert Trust Controls', 'Defense Evasion'],
};

// ─── Category-level fallback mapping ────────────────────────────────────────
const CATEGORY_TECHNIQUES = {
    injection: { primary: 'T1190', techniques: ['T1190', 'T1059', 'T1068', 'T1210'] },
    ssl:       { primary: 'T1190', techniques: ['T1190', 'T1040', 'T1552', 'T1557', 'T1078'] },
    headers:   { primary: 'T1190', techniques: ['T1190', 'T1189', 'T1059.007', 'T1078'] },
    dns:       { primary: 'T1071', techniques: ['T1071', 'T1568', 'T1553', 'T1190'] },
    ports:     { primary: 'T1046', techniques: ['T1046', 'T1595', 'T1135', 'T1190', 'T1210'] },
    misconfig: { primary: 'T1190', techniques: ['T1190', 'T1068', 'T1548', 'T1078', 'T1562'] },
    other:     { primary: 'T1190', techniques: ['T1190', 'T1046', 'T1068'] },
};

// ─── Title/description keyword overrides (more specific than category) ──────
const KEYWORD_OVERRIDES = [
    [/xss|reflected|cross-site|cookie|session/i, 'T1189', ['T1189', 'T1059.007', 'T1539', 'T1185']],
    [/sql|injection/i, 'T1190', ['T1190', 'T1059', 'T1068', 'T1210']],
    [/csrf|request forgery/i, 'T1189', ['T1189', 'T1078', 'T1539']],
    [/brute force|weak password|default credential/i, 'T1110', ['T1110', 'T1078', 'T1021']],
    [/ddos|denial of service|dos/i, 'T1498', ['T1498', 'T1499', 'T1485']],
    [/outdated|deprecated|end.?of.?life|obsolete|old version/i, 'T1190', ['T1190', 'T1210', 'T1068']],
    [/sniff|plaintext|cleartext|weak cipher/i, 'T1040', ['T1040', 'T1552', 'T1557']],
    [/directory listing|information disclosure|verbose error/i, 'T1005', ['T1005', 'T1082', 'T1590']],
];

const PHASE_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
];

function toTechnique(id) {
    const entry = TECHNIQUE_LIBRARY[id];
    if (!entry) return null;
    return { id, name: entry[0], tactic: entry[1] };
}

/**
 * Map a single vulnerability to MITRE ATT&CK techniques.
 * @param {object} vuln - vulnerability row with title/description/category
 * @returns {{ primary: object|null, techniques: object[], tactics: string[] }}
 */
function mapToMitreAttack(vuln) {
    const title = vuln.title || '';
    const desc = vuln.description || '';
    const cat = String(vuln.category || '').toLowerCase();
    const haystack = `${title} ${desc}`;

    let matched = null;
    for (const [re, primaryId, techniqueIds] of KEYWORD_OVERRIDES) {
        if (re.test(haystack)) { matched = { primaryId, techniqueIds }; break; }
    }
    if (!matched) {
        const base = CATEGORY_TECHNIQUES[cat] || CATEGORY_TECHNIQUES.other;
        matched = { primaryId: base.primary, techniqueIds: base.techniques };
    }

    const primary = toTechnique(matched.primaryId);
    const rest = matched.techniqueIds.map(toTechnique).filter(Boolean).filter(t => t.id !== matched.primaryId);
    const techniques = [primary, ...rest].filter(Boolean).slice(0, 6);
    const tactics = [...new Set(techniques.map(t => t.tactic))];

    return { primary, techniques, tactics };
}

/**
 * Build an assessment-level ATT&CK attack map from a list of vulnerabilities.
 * @param {object[]} vulns
 * @returns {{ techniques: object[], phases: object[], totalTechniques: number }}
 */
function buildAttackMap(vulns) {
    const techniqueCount = new Map();

    for (const v of vulns || []) {
        const m = mapToMitreAttack(v);
        for (const t of m.techniques) {
            const cur = techniqueCount.get(t.id) || { id: t.id, name: t.name, tactic: t.tactic, count: 0 };
            cur.count += 1;
            techniqueCount.set(t.id, cur);
        }
    }

    const techniques = [...techniqueCount.values()].sort((a, b) => b.count - a.count);

    const phaseMap = new Map();
    for (const t of techniques) {
        const arr = phaseMap.get(t.tactic) || [];
        arr.push(t.id);
        phaseMap.set(t.tactic, arr);
    }

    const phases = PHASE_ORDER
        .filter(p => phaseMap.has(p))
        .map(p => ({
            phase: p,
            techniqueIds: phaseMap.get(p),
            techniqueCount: phaseMap.get(p).length,
            covered: true,
        }));

    return { techniques, phases, totalTechniques: techniques.length };
}

module.exports = { mapToMitreAttack, buildAttackMap, TECHNIQUE_LIBRARY, PHASE_ORDER };
