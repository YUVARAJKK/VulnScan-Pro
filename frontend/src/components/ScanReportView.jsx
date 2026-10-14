import { useState, useMemo, useCallback } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { scanAPI } from '../services/api';

import {
    CONSOLE, SEV_CONFIG, SEV_ORDER, AnimatedCount, GlassCard, SectionTitle,
    ConsoleButton, SeverityPill, StatusPill, ConsoleTabs, CopyButton,
} from './console';

ChartJS.register(ArcElement, Tooltip, Legend);

/* ─────────────────────────────────────────────────────────────────────────────
   VulnScan Pro — Unified Assessment Console
   The single source of truth for scan results across the entire platform.
   Both the public report page (shareable link) and the authenticated scan
   detail page render THIS component, guaranteeing identical design, metrics,
   severity distribution and risk scoring — no more public-vs-account mismatch.

   Layout is inspired by the world's best security platforms (Tenable, Intruder,
   Pentera, HackerOne): a command-center header, an executive overview with a
   risk gauge, severity telemetry, an interactive MITRE ATT&CK attack map,
   professional findings triage, and compliance posture — plus one-click
   exports of consulting-grade PDF/XML/JSON/CSV reports.
   ───────────────────────────────────────────────────────────────────────────── */

const FONT = CONSOLE.FONT;
const MONO = CONSOLE.MONO;
const PANEL_BORDER = '#E2E8F0';

const PRIORITY = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P5' };

const CATEGORY_LABELS = {
    ports: 'Network Services', ssl: 'SSL / TLS', headers: 'HTTP Headers', dns: 'DNS Configuration',
    injection: 'Injection', misconfig: 'Misconfiguration', other: 'Other',
};
const categoryLabel = c => CATEGORY_LABELS[String(c || '').toLowerCase()] || (c ? c.charAt(0).toUpperCase() + c.slice(1) : 'Other');

// Fallback attribution only — findings produced by the Python engine carry the
// real detector name in `detectedBy` (security_headers, cookie_security, cors,
// xss, sqli, open_redirect, path_traversal, ...).
const SCANNER_FROM_CAT = {
    ports: 'custom-engine', ssl: 'custom-engine', headers: 'security_headers', dns: 'custom-engine',
    injection: 'custom-engine', misconfig: 'custom-engine', other: 'custom-engine',
};

/* ─── Unified severity counts — the single source of truth for every number ─
   Server counts win when present; otherwise counts are recomputed from the
   actual finding rows, killing the "0 findings" display bug forever. */
export function normalizeCounts(scan, vulns) {
    const api = scan?.severityCounts || scan?.severitySummary || {};
    const sum = SEV_ORDER.reduce((a, k) => a + (Number(api[k]) || 0), 0);
    if (sum > 0) return SEV_ORDER.reduce((a, k) => ({ ...a, [k]: Number(api[k]) || 0 }), {});
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns || []) if (c[v.severity] !== undefined) c[v.severity] += 1;
    return c;
}

/* ─── Unified risk model — identical to the backend scoring (public worker +
   ReportGenerator) so grades, risk scores and threat levels always match the
   PDF / JSON / XML exports. Higher score = higher risk. */
export function computeRisk(scan, counts, vulns) {
    // Canonical severity-band model — mirrors backend/src/utils/riskScoring.js and
    // scanner_engine/analysis/severity.py: critical=70, high=50, medium=30, low=10.
    const points = (counts.critical || 0) * 70 + (counts.high || 0) * 50 + (counts.medium || 0) * 30 + (counts.low || 0) * 10;
    const server = Number(scan?.riskScore);
    const riskScore = Number.isFinite(server) && server >= 0 ? Math.min(100, Math.round(server)) : Math.min(100, points);
    const healthScore = Math.max(0, 100 - riskScore);
    let grade;
    if (healthScore >= 95) grade = 'A+';
    else if (healthScore >= 85) grade = 'A';
    else if (healthScore >= 75) grade = 'B';
    else if (healthScore >= 60) grade = 'C';
    else if (healthScore >= 40) grade = 'D';
    else grade = 'F';
    const rating = riskScore >= 70
        ? { label: 'CRITICAL', color: '#dc2626', description: 'Immediate remediation required — critical vulnerabilities pose severe risk to business operations.' }
        : riskScore >= 50
            ? { label: 'HIGH', color: '#ea580c', description: 'High-priority vulnerabilities require urgent attention and remediation.' }
            : riskScore >= 30
                ? { label: 'MODERATE', color: '#ca8a04', description: 'Moderate security risk — address within standard remediation timelines.' }
                : riskScore >= 10
                    ? { label: 'LOW', color: '#2563eb', description: 'Low security risk — schedule remediation in the next maintenance window.' }
                    : { label: 'SECURE', color: '#16a34a', description: 'No significant vulnerabilities detected. Continue regular assessment cadence.' };
    return { riskScore, healthScore, grade, rating };
}

const OWASP_CATEGORIES = {
    'injection': 'A03:2021 – Injection', 'xss': 'A03:2021 – Injection', 'sql injection': 'A03:2021 – Injection',
    'broken access control': 'A01:2021 – Broken Access Control', 'idor': 'A01:2021 – Broken Access Control',
    'ssrf': 'A10:2021 – Server-Side Request Forgery', 'cryptographic': 'A02:2021 – Cryptographic Failures',
    'ssl': 'A02:2021 – Cryptographic Failures', 'tls': 'A02:2021 – Cryptographic Failures',
    'authentication': 'A07:2021 – Identification and Authentication Failures',
    'misconfiguration': 'A05:2021 – Security Misconfiguration', 'outdated': 'A06:2021 – Vulnerable and Outdated Components',
    'logging': 'A09:2021 – Security Logging and Monitoring Failures',
};
function getOwaspCategory(category, title) {
    const text = ((category || '') + ' ' + (title || '')).toLowerCase();
    for (const [key, val] of Object.entries(OWASP_CATEGORIES)) if (text.includes(key)) return val;
    return 'A05:2021 – Security Misconfiguration';
}

/* ─── MITRE ATT&CK® mapping (mirrors backend src/utils/mitreMapping.js) ─────── */
const MITRE_LIB = {
    T1595: ['Active Scanning', 'Reconnaissance'], T1590: ['Gather Victim Network Information', 'Reconnaissance'],
    T1190: ['Exploit Public-Facing Application', 'Initial Access'], T1189: ['Drive-by Compromise', 'Initial Access'],
    T1195: ['Supply Chain Compromise', 'Initial Access'], T1078: ['Valid Accounts', 'Defense Evasion'],
    T1110: ['Brute Force', 'Credential Access'], T1059: ['Command and Scripting Interpreter', 'Execution'],
    'T1059.007': ['JavaScript / JScript', 'Execution'], T1068: ['Exploitation for Privilege Escalation', 'Privilege Escalation'],
    T1548: ['Abuse Elevation Control Mechanism', 'Privilege Escalation'], T1562: ['Impair Defenses', 'Defense Evasion'],
    T1070: ['Indicator Removal', 'Defense Evasion'], T1040: ['Network Sniffing', 'Credential Access'],
    T1552: ['Unsecured Credentials', 'Credential Access'], T1557: ['Adversary-in-the-Middle', 'Credential Access'],
    T1539: ['Steal Web Session Cookie', 'Credential Access'], T1185: ['Browser Session Hijacking', 'Collection'],
    T1005: ['Data from Local System', 'Collection'], T1046: ['Network Service Discovery', 'Discovery'],
    T1135: ['Network Share Discovery', 'Discovery'], T1082: ['System Information Discovery', 'Discovery'],
    T1210: ['Exploitation of Remote Services', 'Lateral Movement'], T1021: ['Remote Services', 'Lateral Movement'],
    T1071: ['Application Layer Protocol', 'Command and Control'], T1568: ['Dynamic Resolution', 'Command and Control'],
    T1105: ['Ingress Tool Transfer', 'Command and Control'], T1041: ['Exfiltration Over C2 Channel', 'Exfiltration'],
    T1567: ['Exfiltration Over Web Service', 'Exfiltration'], T1485: ['Data Destruction', 'Impact'],
    T1498: ['Network Denial of Service', 'Impact'], T1499: ['Endpoint Denial of Service', 'Impact'],
    T1553: ['Subvert Trust Controls', 'Defense Evasion'],
};
const MITRE_CAT = {
    injection: { p: 'T1190', t: ['T1190', 'T1059', 'T1068', 'T1210'] }, ssl: { p: 'T1190', t: ['T1190', 'T1040', 'T1552', 'T1557', 'T1078'] },
    headers: { p: 'T1190', t: ['T1190', 'T1189', 'T1059.007', 'T1078'] }, dns: { p: 'T1071', t: ['T1071', 'T1568', 'T1553', 'T1190'] },
    ports: { p: 'T1046', t: ['T1046', 'T1595', 'T1135', 'T1190', 'T1210'] }, misconfig: { p: 'T1190', t: ['T1190', 'T1068', 'T1548', 'T1078', 'T1562'] },
    other: { p: 'T1190', t: ['T1190', 'T1046', 'T1068'] },
};
const MITRE_KEYWORDS = [
    [/xss|reflected|cross-site|cookie|session/i, 'T1189', ['T1189', 'T1059.007', 'T1539', 'T1185']],
    [/sql|injection/i, 'T1190', ['T1190', 'T1059', 'T1068', 'T1210']],
    [/csrf|request forgery/i, 'T1189', ['T1189', 'T1078', 'T1539']],
    [/brute force|weak password|default credential/i, 'T1110', ['T1110', 'T1078', 'T1021']],
    [/ddos|denial of service|dos/i, 'T1498', ['T1498', 'T1499', 'T1485']],
    [/outdated|deprecated|end.?of.?life|obsolete|old version/i, 'T1190', ['T1190', 'T1210', 'T1068']],
    [/sniff|plaintext|cleartext|weak cipher/i, 'T1040', ['T1040', 'T1552', 'T1557']],
    [/directory listing|information disclosure|verbose error/i, 'T1005', ['T1005', 'T1082', 'T1590']],
];
const MITRE_PHASE_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
];
function getMitre(vuln) {
    const haystack = `${vuln.title || ''} ${vuln.description || ''}`;
    const cat = String(vuln.category || '').toLowerCase();
    let match = null;
    for (const [re, p, t] of MITRE_KEYWORDS) { if (re.test(haystack)) { match = { p, t }; break; } }
    if (!match) { const base = MITRE_CAT[cat] || MITRE_CAT.other; match = { p: base.p, t: base.t }; }
    const toTech = id => { const e = MITRE_LIB[id]; return e ? { id, name: e[0], tactic: e[1] } : null; };
    const primary = toTech(match.p);
    const rest = match.t.map(toTech).filter(Boolean).filter(t => t.id !== match.p);
    const techniques = [primary, ...rest].filter(Boolean).slice(0, 6);
    return { primary: primary || null, techniques, tactics: [...new Set(techniques.map(t => t.tactic))] };
}
function buildAttackMap(vulns) {
    const countMap = new Map();
    for (const v of vulns || []) for (const t of getMitre(v).techniques) {
        const cur = countMap.get(t.id) || { id: t.id, name: t.name, tactic: t.tactic, count: 0 };
        cur.count += 1; countMap.set(t.id, cur);
    }
    const techniques = [...countMap.values()].sort((a, b) => b.count - a.count);
    const phaseMap = new Map();
    for (const t of techniques) { const arr = phaseMap.get(t.tactic) || []; arr.push(t.id); phaseMap.set(t.tactic, arr); }
    const phases = MITRE_PHASE_ORDER.filter(p => phaseMap.has(p)).map(p => ({
        phase: p, techniqueIds: phaseMap.get(p), techniqueCount: phaseMap.get(p).length, covered: true,
    }));
    return { techniques, phases, totalTechniques: techniques.length };
}

/* ─── Exploit intel heuristic (clearly labeled as such) ───────────────────── */
function exploitIntel(vuln) {
    const hasCve = !!vuln.cveId;
    const s = vuln.severity;
    if (hasCve && (s === 'critical' || s === 'high')) return { label: 'EXPLOIT LIKELY', tone: '#dc2626', tip: 'Public PoC / exploit-db coverage likely for this CVE' };
    if (hasCve) return { label: 'CVE TRACKED', tone: '#0891B2', tip: 'Documented CVE — verify patch status' };
    if (s === 'critical') return { label: 'HIGH IMPACT', tone: '#ea580c', tip: 'No CVE mapped — escalate manually' };
    return null;
}

const INTEL_CONTEXT = {
    'Initial Access': 'Top CISA KEV entry point; favored by APT groups',
    'Credential Access': 'Frequently chained with brute-force & phishing campaigns',
    'Discovery': 'Standard post-compromise recon; low detection signal',
    'Lateral Movement': 'Rapid spread enabler; pair with EDR detection gaps',
    'Execution': 'Commonly weaponized via web shells & script interpreters',
    'Exfiltration': 'Indicates established C2; incident-response priority',
    'Command and Control': 'Signals persistent attacker presence',
};

const STATUS_OPTS = [
    { value: 'open',           label: 'Open',           color: '#dc2626' },
    { value: 'resolved',       label: 'Resolved',       color: '#059669' },
    { value: 'ignored',        label: 'Ignored',        color: '#0E7490' },
    { value: 'false_positive', label: 'False Positive', color: '#64748b' },
];

const GLOBAL_STYLES = `
    @keyframes srvSpin { to { transform: rotate(360deg); } }
    @keyframes srvFadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
    @keyframes srvPulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
    @keyframes srvShimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
    .srv-row { transition: background .15s; }
    .srv-row:hover { background: rgba(6,182,212,0.045); }
    @media (max-width: 980px) { .srv-grid-2 { grid-template-columns: 1fr !important; } .srv-hide-sm { display: none !important; } }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 10px; }
`;

/* ─── Primitives ─────────────────────────────────────────────────────────── */

function ScoreGauge({ score, grade, size = 200 }) {
    const clamped = Math.max(0, Math.min(100, Number(score) || 0));
    const stroke = 15, r = (size - stroke) / 2 - 6;
    const cx = size / 2, cy = size / 2 - 6;
    const circ = Math.PI * r;
    const filled = (clamped / 100) * circ;
    const color = clamped >= 80 ? '#dc2626' : clamped >= 60 ? '#ea580c' : clamped >= 40 ? '#ca8a04' : clamped >= 20 ? '#0891B2' : '#16a34a';
    const arc = `M ${cx - r},${cy} A ${r},${r} 0 0 1 ${cx + r},${cy}`;
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <svg width={size} height={size / 2 + 26} style={{ overflow: 'visible' }}>
                <path d={arc} stroke="#E2E8F0" strokeWidth={stroke} fill="none" strokeLinecap="round" />
                <path d={arc} stroke={color} strokeWidth={stroke} fill="none" strokeLinecap="round"
                    strokeDasharray={`${filled} ${circ}`} style={{ transition: 'stroke-dasharray 1.2s ease', filter: 'none' }} />
                <text x={cx} y={cy - 6} textAnchor="middle" fontSize={40} fontWeight={800} fill="#0f172a" fontFamily={FONT}>{clamped}</text>
                <text x={cx} y={cy + 14} textAnchor="middle" fontSize={9.5} fontWeight={700} fill="#64748b" letterSpacing="0.14em" fontFamily={FONT}>RISK SCORE / 100</text>
            </svg>
            <span style={{
                marginTop: 6, padding: '4px 16px', borderRadius: 999, fontSize: 12, fontWeight: 800,
                color, background: `${color}12`, border: `1px solid ${color}35`, letterSpacing: '0.08em', fontFamily: MONO,
            }}>
                GRADE {grade || '—'}
            </span>
        </div>
    );
}

function SeverityDonut({ counts, total }) {
    const hasData = total > 0;
    const chartData = {
        labels: SEV_ORDER.map(k => SEV_CONFIG[k].label),
        datasets: [{
            data: SEV_ORDER.map(k => counts[k] || 0),
            backgroundColor: SEV_ORDER.map(k => SEV_CONFIG[k].color),
            borderColor: '#FFFFFF', borderWidth: 3, hoverOffset: 8,
        }],
    };
    const options = {
        cutout: '72%', responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: '#0F172A', padding: 12, borderColor: PANEL_BORDER, borderWidth: 1,
                titleFont: { family: FONT, size: 12 }, bodyFont: { family: FONT, size: 12 },
                callbacks: { label: c => ` ${c.label}: ${c.parsed || 0} (${total > 0 ? Math.round(((c.parsed || 0) / total) * 100) : 0}%)` },
            },
        },
    };
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 22, flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: 170, height: 170, flexShrink: 0 }}>
                {hasData ? <Doughnut data={chartData} options={options} /> : (
                    <div style={{ width: '100%', height: '100%', borderRadius: '50%', background: '#F8FAFC', border: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, color: '#64748b', fontFamily: FONT }}>No data</div>
                )}
                <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
                    <span style={{ fontSize: 24, fontWeight: 800, color: '#0f172a', fontFamily: FONT }}>{total}</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: '#64748b', letterSpacing: '0.12em', textTransform: 'uppercase', fontFamily: MONO }}>Findings</span>
                </div>
            </div>
            <div style={{ flex: 1, minWidth: 190 }}>
                {SEV_ORDER.map(k => {
                    const cfg = SEV_CONFIG[k];
                    const count = counts[k] || 0;
                    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                    return (
                        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 9 }}>
                            <span style={{ width: 9, height: 9, borderRadius: 3, background: cfg.color, boxShadow: 'none', flexShrink: 0 }} />
                            <span style={{ width: 60, fontSize: 12, fontWeight: 600, color: '#475569', fontFamily: FONT }}>{cfg.label}</span>
                            <div style={{ flex: 1, height: 7, background: '#EEF2F6', borderRadius: 4, overflow: 'hidden' }}>
                                <div style={{ height: '100%', width: `${Math.max(count > 0 ? 4 : 0, pct)}%`, background: `linear-gradient(90deg, ${cfg.color}88, ${cfg.color})`, borderRadius: 4, transition: 'width .7s ease', boxShadow: 'none' }} />
                            </div>
                            <span style={{ width: 72, textAlign: 'right', fontSize: 12, color: '#64748b', fontVariantNumeric: 'tabular-nums', fontFamily: MONO }}>
                                <strong style={{ color: '#1e293b' }}>{count}</strong> ({pct}%)
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function ReconLog({ vulns, scan }) {
    const lines = [];
    const catSet = new Set();
    for (const v of vulns || []) catSet.add((v.category || 'other').toLowerCase());
    for (const c of catSet) lines.push({ src: SCANNER_FROM_CAT[c] || 'engine', msg: `enumeration complete — ${categoryLabel(c)} surface mapped`, tone: '#0891B2' });
    const events = (vulns || []).slice(0, 12).map(v => ({
        src: SCANNER_FROM_CAT[(v.category || 'other').toLowerCase()] || 'engine',
        msg: `${v.title} [${(v.severity || 'info').toUpperCase()}]${v.cveId ? ' · ' + v.cveId : ''}`,
        tone: (SEV_CONFIG[v.severity] || SEV_CONFIG.info).color,
    }));
    lines.push(...events);
    const host = scan?.hostname || scan?.asset?.target || scan?.targetUrl || 'target';
    return (
        <GlassCard style={{ padding: 16 }} hover={false}>
            <SectionTitle title="Recon Telemetry" sub="Live signal stream derived from this assessment" accent="#0891B2" />
            <div style={{ fontFamily: MONO, fontSize: 13, lineHeight: 1.9, maxHeight: 220, overflowY: 'auto', paddingRight: 6 }}>
                <p style={{ margin: 0, color: '#475569' }}>$ vulnscan --target {host} --engine full --intel on</p>
                <p style={{ margin: 0, color: '#475569' }}>&gt; {(vulns || []).length} signals · 7 scanners · threat intel feed: attached</p>
                {lines.map((l, i) => (
                    <p key={i} style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                        <span style={{ color: '#475569' }}>[</span><span style={{ color: '#16a34a' }}>{String(i + 1).padStart(2, '0')}</span><span style={{ color: '#475569' }}>] </span>
                        <span style={{ color: '#0891B2' }}>{l.src.padEnd(14, ' ')}</span>
                        <span style={{ color: l.tone }}>{l.msg}</span>
                    </p>
                ))}
            </div>
        </GlassCard>
    );
}

function ThreatIntelPanel({ attackMap }) {
    const techs = (attackMap?.techniques || []).slice(0, 5);
    if (techs.length === 0) return null;
    return (
        <GlassCard style={{ padding: 16 }} hover={false}>
            <SectionTitle title="Threat Context" sub="Heuristic intel for top mapped techniques" accent="#0891B2" />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {techs.map(t => (
                    <div key={t.id} style={{ background: '#F8FAFC', border: '1px solid #E8EDF2', borderRadius: 10, padding: '11px 13px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                            <a href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noopener noreferrer" style={{ fontFamily: MONO, fontWeight: 700, fontSize: 13, color: '#0891B2', textDecoration: 'none' }}>{t.id} ↗</a>
                            <span style={{ fontSize: 12, fontWeight: 600, color: '#1e293b', fontFamily: FONT }}>{t.name}</span>
                            <span style={{ fontSize: 13, fontWeight: 700, color: '#475569', background: '#EEF2F6', borderRadius: 999, padding: '2px 8px', fontFamily: MONO }}>×{t.count}</span>
                        </div>
                        {INTEL_CONTEXT[t.tactic] && <p style={{ margin: 0, fontSize: 13, color: '#64748b', fontFamily: FONT }}>{INTEL_CONTEXT[t.tactic]}</p>}
                    </div>
                ))}
            </div>
            <p style={{ margin: '10px 0 0', fontSize: 12, color: '#475569', fontFamily: FONT }}>Context tags are heuristic correlations for triage, not attributions.</p>
        </GlassCard>
    );
}

function DetailRow({ label, value, mono }) {
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 12 }}>
            <span style={{ color: '#64748b', flexShrink: 0, fontFamily: FONT }}>{label}</span>
            <span style={{ fontWeight: 600, color: '#334155', textAlign: 'right', minWidth: 0, overflowWrap: 'anywhere', fontFamily: mono ? MONO : FONT, fontSize: mono ? 11 : 12 }}>
                {value}
            </span>
        </div>
    );
}

function MitreBlock({ mitre }) {
    if (!mitre || !mitre.primary) return null;
    const related = (mitre.techniques || []).filter(t => t.id !== mitre.primary.id);
    return (
        <div style={{ background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.25)', borderRadius: 10, padding: '13px 16px' }}>
            <p style={{ fontSize: 12, fontWeight: 700, color: '#0891B2', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 10px', fontFamily: MONO }}>MITRE ATT&CK MAPPING</p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: related.length ? 10 : 0 }}>
                <a href={`https://attack.mitre.org/techniques/${mitre.primary.id}/`} target="_blank" rel="noopener noreferrer" style={{ fontFamily: MONO, fontWeight: 800, fontSize: 12, color: '#0E7490', textDecoration: 'none' }}>{mitre.primary.id} ↗</a>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#1e293b', overflowWrap: 'anywhere', fontFamily: FONT }}>{mitre.primary.name}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#0E7490', background: 'rgba(6,182,212,0.15)', borderRadius: 999, padding: '2px 9px', fontFamily: FONT }}>{mitre.primary.tactic}</span>
            </div>
            {related.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {related.map(t => (
                        <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: '#475569', background: '#F1F5F9', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 999, padding: '3px 9px', textDecoration: 'none', fontWeight: 500, overflowWrap: 'anywhere', fontFamily: FONT }}>{t.id} · {t.name}</a>
                    ))}
                </div>
            )}
        </div>
    );
}

/* ─── ML classification block (from the Python engine's Random Forest) ───── */
const ML_STATUS = {
    confirmed:            { label: 'CONFIRMED',            color: '#16a34a', tip: 'High-confidence genuine finding (model probability ≥ 0.85)' },
    likely:               { label: 'LIKELY',               color: '#16a34a', tip: 'Moderate-confidence genuine finding — verify before remediation' },
    suspected:            { label: 'SUSPECTED',            color: '#ca8a04', tip: 'Low confidence — manual verification recommended' },
    likely_false_positive:{ label: 'LIKELY FALSE POSITIVE',color: '#64748b', tip: 'Model considers this likely a false positive — review before discarding' },
    inconclusive:         { label: 'INCONCLUSIVE',         color: '#ea580c', tip: 'Ambiguous result — manual verification required' },
};

function MlBlock({ ml }) {
    if (!ml) return null;
    const st = ML_STATUS[ml.verification_status] || ML_STATUS.inconclusive;
    const isMl = ml.classification_method === 'ml_random_forest';
    const probPct = typeof ml.positive_probability === 'number' ? Math.round(ml.positive_probability * 100) : null;
    return (
        <div style={{ background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 10, padding: '13px 16px', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                <p style={{ fontSize: 12, fontWeight: 700, color: '#16a34a', textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0, fontFamily: MONO }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ verticalAlign: -1, marginRight: 5 }}><path d="M12 2a5 5 0 0 1 5 5c0 2.4-1.7 4.4-4 4.9V14h2a1 1 0 0 1 1 1v2h1a1 1 0 0 1 1 1v3H7v-3a1 1 0 0 1 1-1h1v-2a1 1 0 0 1 1-1h2v-2.1c-2.3-.5-4-2.5-4-4.9a5 5 0 0 1 5-5z" /></svg>
                    AI/ML Classification
                </p>
                <span title={st.tip} style={{ fontSize: 13, fontWeight: 800, color: st.color, border: `1px solid ${st.color}55`, background: `${st.color}12`, borderRadius: 5, padding: '2px 7px', fontFamily: MONO }}>{st.label}</span>
            </div>
            {probPct !== null && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <div style={{ flex: 1, height: 6, borderRadius: 3, background: '#E8EDF2', overflow: 'hidden' }}>
                        <div style={{ width: `${probPct}%`, height: '100%', borderRadius: 3, background: 'linear-gradient(90deg,#16a34a,#16a34a)' }} />
                    </div>
                    <span style={{ fontSize: 12.5, fontWeight: 700, color: '#15803d', fontFamily: MONO, minWidth: 62, textAlign: 'right' }}>{probPct}% genuine</span>
                </div>
            )}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 14px', fontSize: 12.5, color: '#475569', fontFamily: MONO }}>
                <span>method: {isMl ? 'Random Forest' : 'rule-based fallback'}</span>
                {ml.model_version && ml.model_version !== 'none' && <span>model: {ml.model_version}</span>}
                {ml.schema_version && <span>schema: v{ml.schema_version}</span>}
                {typeof ml.threshold === 'number' && <span>threshold: {ml.threshold}</span>}
            </div>
            {ml.note && (
                <p style={{ fontSize: 13, color: '#475569', lineHeight: 1.6, margin: '8px 0 0', fontFamily: FONT }}>{ml.note}</p>
            )}
            <p style={{ fontSize: 12, color: '#64748b', margin: '8px 0 0', lineHeight: 1.5, fontFamily: FONT }}>
                Classification is a probability estimate, not proof of exploitation. Keep high-impact findings in the review queue regardless of model confidence.
            </p>
        </div>
    );
}

/* ─── AI Remediation engine (authenticated flows only) ───────────────────── */
function AiRemediationPanel({ vulnId }) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [activeTab, setActiveTab] = useState('immediate');

    const generate = useCallback(async () => {
        setLoading(true); setError('');
        try {
            const res = await scanAPI.getAiRemediation(vulnId);
            setData(res.data.data);
        } catch {
            setError('AI engine unavailable. Please try again in a moment.');
        } finally { setLoading(false); }
    }, [vulnId]);

    const isAI = data?.meta?.aiPowered;

    const tabs = [
        { key: 'immediate', label: 'Immediate' },
        { key: 'code',      label: 'Code Fix' },
        { key: 'mitre',     label: 'MITRE' },
        { key: 'hardening', label: 'Hardening' },
        { key: 'compliance', label: 'Compliance' },
    ].filter(t => {
        if (t.key === 'code' && !data?.remediation?.codeExample) return false;
        if (t.key === 'compliance' && !data?.remediation?.complianceImpact?.length) return false;
        if (t.key === 'mitre' && !data?.vulnerability?.mitreAttack?.length) return false;
        return true;
    });

    return (
        <GlassCard style={{ marginTop: 18, padding: 0, overflow: 'hidden' }} hover={false}>
            <div style={{ background: 'linear-gradient(135deg, #F8FAFC 0%, #FFFFFF 100%)', borderBottom: '1px solid #E2E8F0', padding: '14px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                    <div style={{ width: 34, height: 34, borderRadius: 9, background: 'linear-gradient(135deg,#0891B2,#0891B2)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 16px rgba(6,182,212,0.35)' }}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>
                    </div>
                    <div>
                        <p style={{ fontSize: 13, fontWeight: 700, color: '#1e293b', margin: 0, fontFamily: FONT }}>
                            AI Security Remediation Engine
                            {isAI && <span style={{ marginLeft: 8, fontSize: 12, background: 'rgba(6,182,212,0.2)', color: '#67e8f9', padding: '2px 7px', borderRadius: 4, fontWeight: 700, border: '1px solid rgba(6,182,212,0.3)' }}>CLAUDE AI</span>}
                        </p>
                        <p style={{ fontSize: 13, color: '#64748b', margin: 0, fontFamily: FONT }}>
                            {isAI ? 'Powered by Claude — MITRE ATT&CK + NIST CSF 2.0 mapped' : 'Pattern-matched remediation with MITRE ATT&CK mapping'}
                        </p>
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {data && (
                        <>
                            <span style={{ fontSize: 13, color: '#059669', fontWeight: 700, fontFamily: MONO }}>✓ ANALYSIS COMPLETE</span>
                            <span style={{ fontSize: 12, color: '#64748b', background: '#F1F5F9', padding: '2px 8px', borderRadius: 4, border: '1px solid #E2E8F0', fontFamily: MONO }}>v{data.meta?.engineVersion}</span>
                            <button onClick={() => setData(null)} style={{ fontSize: 13, color: '#0891B2', background: 'none', border: '1px solid rgba(6,182,212,0.3)', cursor: 'pointer', padding: '4px 10px', borderRadius: 7, fontWeight: 700, fontFamily: FONT }}>↻ Refresh</button>
                        </>
                    )}
                    {!data && (
                        <ConsoleButton onClick={generate} busy={loading} style={{ padding: '8px 16px', fontSize: 12 }}>
                            {loading ? 'Analyzing…' : 'Generate Remediation'}
                        </ConsoleButton>
                    )}
                </div>
            </div>

            {error && <div style={{ padding: '12px 20px', background: 'rgba(239,68,68,0.08)', color: '#dc2626', fontSize: 13, borderBottom: '1px solid rgba(239,68,68,0.2)', fontFamily: FONT }}>⚠ {error}</div>}

            {!data && !loading && !error && (
                <div style={{ padding: '34px 20px', textAlign: 'center' }}>
                    <div style={{ width: 48, height: 48, borderRadius: 13, background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.18)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0891B2" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                    </div>
                    <p style={{ color: '#475569', fontSize: 14, fontWeight: 600, marginBottom: 4, fontFamily: FONT }}>AI Remediation Ready</p>
                    <p style={{ color: '#64748b', fontSize: 12, maxWidth: 340, margin: '0 auto', fontFamily: FONT }}>Generate MITRE ATT&CK mapped guidance, code examples, and compliance impact for this vulnerability.</p>
                </div>
            )}

            {data && (
                <>
                    <div style={{ padding: '12px 20px', background: '#F8FAFC', borderBottom: '1px solid #E2E8F0', display: 'flex', flexWrap: 'wrap', gap: 20 }}>
                        {[
                            { label: 'OWASP', value: data.vulnerability?.classification?.owasp, color: '#0E7490' },
                            { label: 'CWE', value: data.vulnerability?.classification?.cwe, color: '#0E7490' },
                            { label: 'Priority', value: data.vulnerability?.priority?.priority, color: data.vulnerability?.priority?.color },
                            { label: 'Fix Timeline', value: data.vulnerability?.priority?.timeline, color: '#475569' },
                            { label: 'Complexity', value: data.vulnerability?.complexity, color: '#ca8a04' },
                            { label: 'Est. Effort', value: data.vulnerability?.estimatedEffort, color: '#15803d' },
                        ].map(({ label, value, color }) => value ? (
                            <div key={label}>
                                <p style={{ fontSize: 13, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2, fontWeight: 700, fontFamily: MONO }}>{label}</p>
                                <p style={{ fontSize: 12, color, fontWeight: 700, fontFamily: label === 'CWE' ? MONO : FONT }}>{value}</p>
                            </div>
                        ) : null)}
                    </div>

                    <div style={{ padding: '16px 20px', background: 'rgba(6,182,212,0.05)', borderBottom: '1px solid #E2E8F0' }}>
                        <p style={{ fontSize: 13, color: '#475569', lineHeight: 1.8, margin: 0, fontFamily: FONT }}>{data.remediation?.summary}</p>
                    </div>

                    <div style={{ display: 'flex', borderBottom: '1px solid #E2E8F0', background: '#F8FAFC', overflowX: 'auto' }}>
                        {tabs.map(tab => (
                            <button key={tab.key} onClick={() => setActiveTab(tab.key)}
                                style={{
                                    padding: '11px 18px', fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', fontFamily: FONT,
                                    borderBottom: activeTab === tab.key ? '2px solid #0891B2' : '2px solid transparent',
                                    background: activeTab === tab.key ? 'rgba(6,182,212,0.09)' : 'transparent',
                                    color: activeTab === tab.key ? '#0E7490' : '#64748b', transition: 'all .15s',
                                }}>
                                {tab.label}
                            </button>
                        ))}
                    </div>

                    <div style={{ padding: 20, minHeight: 170 }}>
                        {activeTab === 'immediate' && (
                            <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                                {data.remediation?.immediateActions?.map((action, i) => (
                                    <li key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '12px 14px', background: 'rgba(239,68,68,0.04)', borderRadius: 10, border: '1px solid rgba(239,68,68,0.14)' }}>
                                        <span style={{ width: 24, height: 24, borderRadius: 7, background: `linear-gradient(135deg, ${i === 0 ? '#dc2626,#dc2626' : i === 1 ? '#ea580c,#ea580c' : '#06b6d4,#0891b2'})`, color: 'white', fontSize: 13, fontWeight: 800, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontFamily: MONO }}>{i + 1}</span>
                                        <p style={{ fontSize: 13, color: '#334155', lineHeight: 1.7, paddingTop: 3, margin: 0, fontFamily: FONT }}>{action}</p>
                                    </li>
                                ))}
                            </ol>
                        )}

                        {activeTab === 'code' && data.remediation?.codeExample && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                {[
                                    { label: 'Vulnerable Code', tone: 'bad', code: data.remediation.codeExample.vulnerable, color: '#dc2626', bg: 'rgba(239,68,68,0.07)', borderColor: 'rgba(239,68,68,0.16)' },
                                    { label: 'Secure Implementation', tone: 'good', code: data.remediation.codeExample.fixed, color: '#16a34a', bg: 'rgba(16,185,129,0.07)', borderColor: 'rgba(16,185,129,0.16)' },
                                ].map(({ label, tone, code, color, bg, borderColor }) => (
                                    <div key={label} style={{ borderRadius: 10, overflow: 'hidden', border: `1px solid ${borderColor}` }}>
                                        <div style={{ padding: '8px 16px', background: bg, fontSize: 13, color, fontWeight: 700, borderBottom: `1px solid ${borderColor}`, display: 'flex', alignItems: 'center', gap: 6, fontFamily: FONT }}>
                                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                                                {tone === 'bad'
                                                    ? <><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></>
                                                    : <polyline points="20 6 9 17 4 12" />}
                                            </svg>
                                            <span>{label}</span>
                                            <span style={{ marginLeft: 'auto', color: '#64748b', fontWeight: 500, fontFamily: MONO }}>({data.remediation.codeExample.language})</span>
                                            <CopyButton text={code} label="Copy" />
                                        </div>
                                        <pre style={{ padding: 16, margin: 0, fontSize: 12, fontFamily: "'JetBrains Mono', Consolas, monospace", color, background: '#F8FAFC', overflowX: 'auto', lineHeight: 1.8 }}>{code}</pre>
                                    </div>
                                ))}
                            </div>
                        )}

                        {activeTab === 'mitre' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                                {data.vulnerability?.mitreAttack?.length > 0 && (
                                    <div>
                                        <p style={{ fontSize: 13, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, fontFamily: MONO }}>MITRE ATT&CK v19.1 Techniques</p>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                            {data.vulnerability.mitreAttack.map((t, i) => (
                                                <a key={i} href={t.url} target="_blank" rel="noopener noreferrer"
                                                    style={{ textDecoration: 'none', display: 'flex', flexDirection: 'column', padding: '10px 14px', background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.22)', borderRadius: 10, minWidth: 180, transition: 'all .15s' }}
                                                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(6,182,212,0.14)'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
                                                    onMouseLeave={e => { e.currentTarget.style.background = 'rgba(6,182,212,0.08)'; e.currentTarget.style.transform = 'none'; }}>
                                                    <span style={{ fontSize: 13, fontFamily: MONO, color: '#0891B2', fontWeight: 700, marginBottom: 4 }}>{t.id}</span>
                                                    <span style={{ fontSize: 12, color: '#1e293b', fontWeight: 600, fontFamily: FONT }}>{t.name}</span>
                                                    <span style={{ fontSize: 12, color: '#64748b', marginTop: 4, fontFamily: FONT }}>Tactic: {t.tactic}</span>
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {data.vulnerability?.nistCsf?.length > 0 && (
                                    <div>
                                        <p style={{ fontSize: 13, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, fontFamily: MONO }}>NIST CSF 2.0 Categories</p>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                            {data.vulnerability.nistCsf.map((n, i) => (
                                                <div key={i} style={{ padding: '8px 14px', background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.22)', borderRadius: 8 }}>
                                                    <p style={{ fontSize: 13, fontFamily: MONO, color: '#16a34a', fontWeight: 700, margin: '0 0 2px' }}>{n.category}</p>
                                                    <p style={{ fontSize: 13, color: '#64748b', margin: 0, fontFamily: FONT }}>{n.description}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {data.vulnerability?.d3fend?.length > 0 && (
                                    <div>
                                        <p style={{ fontSize: 13, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, fontFamily: MONO }}>MITRE D3FEND Countermeasures</p>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                            {data.vulnerability.d3fend.map((d, i) => (
                                                <a key={i} href={d.url} target="_blank" rel="noopener noreferrer"
                                                    style={{ textDecoration: 'none', padding: '8px 14px', background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.22)', borderRadius: 8, display: 'block' }}>
                                                    <span style={{ fontSize: 13, fontFamily: MONO, color: '#ca8a04', fontWeight: 700 }}>{d.id}</span>
                                                    <span style={{ fontSize: 13, color: '#475569', marginLeft: 6, fontFamily: FONT }}>{d.name}</span>
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeTab === 'hardening' && (
                            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                                {data.remediation?.hardeningSteps?.map((step, i) => (
                                    <li key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '11px 14px', background: 'rgba(6,182,212,0.04)', borderRadius: 10, border: '1px solid rgba(6,182,212,0.12)' }}>
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0891B2" strokeWidth="2.5" style={{ flexShrink: 0, marginTop: 2 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                        <p style={{ fontSize: 13, color: '#334155', lineHeight: 1.7, margin: 0, fontFamily: FONT }}>{step}</p>
                                    </li>
                                ))}
                                {data.remediation?.references?.length > 0 && (
                                    <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid #E2E8F0' }}>
                                        <p style={{ fontSize: 12, color: '#475569', marginBottom: 8, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', fontFamily: MONO }}>Reference Materials</p>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                                            {data.remediation.references.map((ref, i) => (
                                                <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer"
                                                    style={{ padding: '4px 12px', background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.22)', borderRadius: 6, fontSize: 13, color: '#0E7490', textDecoration: 'none', fontWeight: 500, fontFamily: FONT }}>
                                                    ↗ {ref.label}
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </ul>
                        )}

                        {activeTab === 'compliance' && (
                            <div>
                                <p style={{ fontSize: 12, color: '#64748b', marginBottom: 14, fontFamily: FONT }}>Compliance frameworks potentially impacted by this vulnerability:</p>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                    {data.remediation?.complianceImpact?.map((item, i) => (
                                        <span key={i} style={{ padding: '6px 14px', background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.22)', borderRadius: 7, fontSize: 12, color: '#ca8a04', fontWeight: 700, fontFamily: FONT }}>
                                            ⚠ {item}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </>
            )}
            <style>{`@keyframes srvSpin { to { transform: rotate(360deg); } }`}</style>
        </GlassCard>
    );
}

/* ─── Finding row (expandable card) ──────────────────────────────────────── */
function FindingRow({ vuln, index, expanded, onToggle, mode }) {
    const sev = SEV_CONFIG[vuln.severity] || SEV_CONFIG.info;
    const mitre = vuln.mitre || getMitre(vuln);
    const intel = exploitIntel(vuln);
    const owaspCat = getOwaspCategory(vuln.category, vuln.title);
    const remedTimeline = vuln.severity === 'critical' ? '0–24 hours' : vuln.severity === 'high' ? '1–7 days' : vuln.severity === 'medium' ? '7–30 days' : '30–90 days';
    const cveLink = vuln.cveId ? `https://www.exploit-db.com/search?cve=${vuln.cveId}` : null;
    const [localStatus, setLocalStatus] = useState(vuln.status || 'open');
    const [updatingStatus, setUpdatingStatus] = useState(false);
    const statusOpt = STATUS_OPTS.find(o => o.value === localStatus) || STATUS_OPTS[0];

    const handleStatusChange = async (e) => {
        e.stopPropagation();
        const newStatus = e.target.value;
        setUpdatingStatus(true);
        try {
            await scanAPI.updateVulnStatus(vuln.id, newStatus);
            setLocalStatus(newStatus);
        } catch { /* keep old status */ }
        finally { setUpdatingStatus(false); }
    };

    return (
        <div style={{ border: `1px solid ${expanded ? sev.border : '#E2E8F0'}`, borderRadius: 13, marginBottom: 10, overflow: 'hidden', background: '#FAFBFC', transition: 'border-color .15s, background .15s' }}>
            <div onClick={onToggle}
                style={{ display: 'flex', alignItems: 'center', gap: 13, padding: '13px 16px', cursor: 'pointer' }}
                onMouseEnter={e => e.currentTarget.style.background = '#F1F5F9'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                <span style={{ fontSize: 13, fontWeight: 700, color: '#475569', fontVariantNumeric: 'tabular-nums', fontFamily: MONO, width: 30, flexShrink: 0 }}>#{String(index + 1).padStart(2, '0')}</span>
                <div style={{ width: 4, alignSelf: 'stretch', borderRadius: 2, background: sev.color, boxShadow: 'none', flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 13.5, fontWeight: 600, color: '#1e293b', margin: 0, wordBreak: 'break-word', fontFamily: FONT }}>{vuln.title}</p>
                    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 4, fontSize: 13, color: '#64748b', fontFamily: MONO }}>
                        {vuln.category && <span>{categoryLabel(vuln.category)}</span>}
                        {vuln.mlVerificationStatus && (
                            <span title={(ML_STATUS[vuln.mlVerificationStatus] || ML_STATUS.inconclusive).tip}
                                style={{ color: (ML_STATUS[vuln.mlVerificationStatus] || ML_STATUS.inconclusive).color, fontWeight: 700, fontSize: 13 }}>
                            ● {(ML_STATUS[vuln.mlVerificationStatus] || ML_STATUS.inconclusive).label}
                            </span>
                        )}
                        {vuln.cveId && <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} style={{ color: '#0891B2', fontWeight: 600, textDecoration: 'none' }}>{vuln.cveId}</a>}
                        {vuln.affectedComponent && <span>{vuln.affectedComponent}</span>}
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                    <span style={{ fontSize: 13, fontWeight: 800, color: sev.color, border: `1px solid ${sev.border}`, borderRadius: 5, padding: '2px 6px', fontFamily: MONO }}>{PRIORITY[vuln.severity] || 'P5'}</span>
                    {intel && (
                        <a href={cveLink || '#'} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} title={intel.tip}
                            style={{ fontSize: 13, fontWeight: 800, color: intel.tone, border: `1px solid ${intel.tone}55`, borderRadius: 5, padding: '2px 6px', fontFamily: MONO, textDecoration: 'none', background: `${intel.tone}12` }}>
                            {intel.label}
                        </a>
                    )}
                    <SeverityPill severity={vuln.severity} />
                    {vuln.cvssScore && Number(vuln.cvssScore) > 0 && (
                        <span style={{ fontSize: 13, fontWeight: 700, color: sev.text, fontFamily: MONO, background: '#F1F5F9', border: '1px solid #E2E8F0', borderRadius: 6, padding: '2px 7px' }}>CVSS {Number(vuln.cvssScore).toFixed(1)}</span>
                    )}
                    {mode === 'auth' && (
                        <span onClick={e => e.stopPropagation()}>
                            <select value={localStatus} onChange={handleStatusChange} disabled={updatingStatus}
                                style={{
                                    appearance: 'none', padding: '5px 26px 5px 10px', borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: 'pointer', fontFamily: FONT,
                                    border: `1px solid ${statusOpt.color}40`, background: `${statusOpt.color}12`, color: statusOpt.color, outline: 'none', transition: 'all .15s',
                                }}>
                                {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                            </select>
                        </span>
                    )}
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2" style={{ transition: 'transform .18s', transform: expanded ? 'rotate(180deg)' : 'none' }}>
                        <polyline points="6 9 12 15 18 9" />
                    </svg>
                </div>
            </div>

            {expanded && (
                <div style={{ borderTop: `1px solid ${sev.border}`, background: '#F8FAFC', padding: '18px 20px' }}>
                    <div className="srv-grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
                        <div>
                            {vuln.description && (
                                <div style={{ marginBottom: 16 }}>
                                    <p style={{ fontSize: 12, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 8px', fontFamily: MONO }}>Description</p>
                                    <p style={{ fontSize: 12.5, color: '#475569', lineHeight: 1.75, margin: 0, overflowWrap: 'anywhere', fontFamily: FONT }}>{vuln.description}</p>
                                </div>
                            )}
                            {vuln.remediation && (
                                <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 10, padding: '13px 16px', marginBottom: 16 }}>
                                    <p style={{ fontSize: 12, fontWeight: 700, color: '#16a34a', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 8px', fontFamily: MONO }}>
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ verticalAlign: -1, marginRight: 5 }}><path d="M20 6L9 17l-5-5" /></svg>
                                        Recommended Remediation
                                    </p>
                                    <p style={{ fontSize: 12.5, color: '#15803d', lineHeight: 1.7, margin: 0, overflowWrap: 'anywhere', fontFamily: FONT }}>{vuln.remediation}</p>
                                </div>
                            )}
                            {vuln.evidence && typeof vuln.evidence === 'object' && Object.keys(vuln.evidence).length > 0 && (
                                <div style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.22)', borderRadius: 10, padding: '13px 16px', marginBottom: 16 }}>
                                    <p style={{ fontSize: 12, fontWeight: 700, color: '#0891B2', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 8px', fontFamily: MONO }}>
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ verticalAlign: -1, marginRight: 5 }}><path d="M10 2v6H4m16 0h-6V2M4 14v6m0-6h6v6m10-6h-6v6" /></svg>
                                        Collected Evidence
                                    </p>
                                    <pre style={{ fontSize: 13, color: '#67e8f9', lineHeight: 1.6, margin: 0, fontFamily: MONO, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 170, overflowY: 'auto' }}>{JSON.stringify(vuln.evidence, null, 2)}</pre>
                                </div>
                            )}
                            <MlBlock ml={vuln.mlClassification} />
                            <MitreBlock mitre={mitre} />
                        </div>
                        <div>
                            <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: 10, padding: '14px 16px' }}>
                                <p style={{ fontSize: 12, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '0 0 12px', fontFamily: MONO }}>Technical Details</p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
                                    <DetailRow label="Severity" value={<span style={{ fontWeight: 700, color: sev.text }}>{sev.label}</span>} />
                                    <DetailRow label="Priority" value={<span style={{ fontWeight: 700, color: sev.color, fontFamily: MONO }}>{PRIORITY[vuln.severity] || 'P5'}</span>} />
                                    {vuln.cvssScore && Number(vuln.cvssScore) > 0 && <DetailRow label="CVSS v3.1 Score" value={<span style={{ fontWeight: 700, color: sev.text, fontFamily: MONO }}>{Number(vuln.cvssScore).toFixed(1)} / 10.0</span>} />}
                                    {vuln.cveId && <DetailRow label="CVE Reference" value={<a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`} target="_blank" rel="noopener noreferrer" style={{ color: '#0891B2', fontWeight: 600, textDecoration: 'none' }}>{vuln.cveId} ↗</a>} />}
                                    {intel && <DetailRow label="Exploit Intel" value={<span style={{ color: intel.tone, fontWeight: 700, fontFamily: MONO }}>{intel.label}</span>} />}
                                    <DetailRow label="Detection Source" value={vuln.detectedBy ? `Custom Engine · ${vuln.detectedBy}` : `Custom Engine · ${SCANNER_FROM_CAT[(vuln.category || '').toLowerCase()] || 'custom-engine'}`} mono />
                                    <DetailRow label="Confidence" value={vuln.confidence ? <span style={{ fontWeight: 700, textTransform: 'uppercase', color: vuln.confidence === 'high' ? '#16a34a' : vuln.confidence === 'medium' ? '#ca8a04' : '#475569', fontFamily: MONO }}>{vuln.confidence}</span> : '—'} />
                                    <DetailRow label="OWASP Mapping" value={owaspCat} />
                                    <DetailRow label="MITRE ATT&CK" value={mitre.primary ? <a href={`https://attack.mitre.org/techniques/${mitre.primary.id}/`} target="_blank" rel="noopener noreferrer" style={{ fontFamily: MONO, fontWeight: 700, color: '#0891B2', textDecoration: 'none' }}>{mitre.primary.id} ↗</a> : 'N/A'} />
                                    <DetailRow label="Remediation SLA" value={<span style={{ fontWeight: 700, color: '#dc2626', fontFamily: MONO }}>{remedTimeline}</span>} />
                                    {vuln.affectedComponent && <DetailRow label="Affected Component" value={vuln.affectedComponent} mono />}
                                    {vuln.endpoint && <DetailRow label="Endpoint" value={vuln.endpoint} mono />}
                                    {vuln.parameter && <DetailRow label="Parameter" value={vuln.parameter} mono />}
                                    {vuln.references && <DetailRow label="References" value={String(vuln.references).split('|')[0].trim()} mono />}
                                </div>
                            </div>
                        </div>
                    </div>
                    {mode === 'auth' && <AiRemediationPanel vulnId={vuln.id} />}
                </div>
            )}
        </div>
    );
}

/* ─── Tabs ───────────────────────────────────────────────────────────────── */

function OverviewTab({ scan, vulns, counts, total, risk, scanDate, scanDuration }) {
    const categories = {};
    for (const v of vulns) { const k = (v.category || 'other').toLowerCase(); categories[k] = (categories[k] || 0) + 1; }
    const catRows = Object.entries(categories).sort((a, b) => b[1] - a[1]);
    const maxCat = catRows.length ? Math.max(...catRows.map(r => r[1])) : 1;
    const catColors = ['#0891B2', '#0E7490', '#0284C7', '#db2777', '#ea580c', '#16a34a', '#64748b'];
    const topCritical = [...vulns].sort((a, b) => {
        const w = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (w[a.severity] ?? 5) - (w[b.severity] ?? 5) || (Number(b.cvssScore) || 0) - (Number(a.cvssScore) || 0);
    }).slice(0, 5);
    const attackMap = buildAttackMap(vulns);
    const target = scan?.asset?.target || scan?.targetUrl || scan?.hostname || 'Target';

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div className="srv-grid-2" style={{ display: 'grid', gridTemplateColumns: '1.15fr 1fr', gap: 18 }}>
                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Assessment Summary" sub="Executive risk overview" />
                    <div style={{ display: 'flex', alignItems: 'center', gap: 26, flexWrap: 'wrap', marginBottom: 18 }}>
                        <ScoreGauge score={risk.riskScore} grade={risk.grade} size={188} />
                        <div style={{ flex: 1, minWidth: 220 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 8 }}>
                                <div style={{ width: 9, height: 9, borderRadius: '50%', background: risk.rating.color, boxShadow: 'none', flexShrink: 0 }} />
                                <p style={{ fontSize: 12.5, fontWeight: 800, color: risk.rating.color, textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0, fontFamily: MONO }}>Threat Level: {risk.rating.label}</p>
                            </div>
                            <p style={{ fontSize: 12.5, color: '#475569', lineHeight: 1.65, margin: 0, fontFamily: FONT }}>{risk.rating.description}</p>
                        </div>
                    </div>
                    <p style={{ fontSize: 12.5, color: '#475569', lineHeight: 1.8, margin: '0 0 16px', fontFamily: FONT }}>
                        A comprehensive security assessment was conducted against <strong style={{ color: '#0f172a' }}>{target}</strong>
                        {' '}on {scanDate.toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}.
                        Identified <strong style={{ color: risk.rating.color }}>{total} security finding{total !== 1 ? 's' : ''}</strong> across {catRows.length} attack surface categories.
                    </p>
                    {counts.critical > 0 && (
                        <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.35)', borderRadius: 10, padding: '11px 14px', fontSize: 12.5, color: '#b91c1c', fontFamily: FONT }}>
                            <strong>{counts.critical} critical vulnerabilit{counts.critical === 1 ? 'y' : 'ies'} require{counts.critical === 1 ? 's' : ''} immediate attention</strong> — address within 24 hours.
                        </div>
                    )}
                </GlassCard>

                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Severity Distribution" sub="Findings by severity level" />
                    <SeverityDonut counts={counts} total={total} />
                </GlassCard>
            </div>

            <div className="srv-grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Attack Surface Breakdown" sub="Findings grouped by category" />
                    {catRows.length === 0 ? (
                        <p style={{ fontSize: 13, color: '#64748b', fontFamily: FONT }}>No findings recorded for this assessment.</p>
                    ) : catRows.map(([key, count], i) => {
                        const color = catColors[i % catColors.length];
                        const pct = Math.round((count / maxCat) * 100);
                        return (
                            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                                <span style={{ width: 128, fontSize: 12, fontWeight: 600, color: '#475569', fontFamily: FONT }}>{categoryLabel(key)}</span>
                                <div style={{ flex: 1, height: 9, background: '#EEF2F6', borderRadius: 5, overflow: 'hidden' }}>
                                    <div style={{ height: '100%', width: `${Math.max(count > 0 ? 5 : 0, pct)}%`, background: `linear-gradient(90deg, ${color}77, ${color})`, borderRadius: 5, transition: 'width .7s ease', boxShadow: 'none' }} />
                                </div>
                                <span style={{ width: 34, textAlign: 'right', fontSize: 12, fontWeight: 700, color: '#1e293b', fontVariantNumeric: 'tabular-nums', fontFamily: MONO }}>{count}</span>
                            </div>
                        );
                    })}
                </GlassCard>

                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Highest Priority Findings" sub="Ranked by severity & CVSS" />
                    {topCritical.length === 0 ? (
                        <p style={{ fontSize: 13, color: '#64748b', fontFamily: FONT }}>No high-priority findings.</p>
                    ) : topCritical.map((v, i) => {
                        const cfg = SEV_CONFIG[v.severity] || SEV_CONFIG.info;
                        return (
                            <div key={v.id || i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '11px 13px', background: '#F8FAFC', border: '1px solid #E8EDF2', borderRadius: 10, marginBottom: 9 }}>
                                <div style={{ width: 24, height: 24, borderRadius: 7, background: cfg.bg, border: `1px solid ${cfg.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, color: cfg.text, fontSize: 13, fontWeight: 800, fontFamily: MONO }}>{i + 1}</div>
                                <div style={{ minWidth: 0 }}>
                                    <p style={{ fontSize: 12.5, fontWeight: 600, color: '#1e293b', margin: '0 0 3px', overflowWrap: 'anywhere', fontFamily: FONT }}>{v.title}</p>
                                    <p style={{ fontSize: 13, color: '#64748b', margin: 0, fontFamily: MONO }}>
                                        {cfg.label}{v.cvssScore && Number(v.cvssScore) > 0 ? ` · CVSS ${Number(v.cvssScore).toFixed(1)}` : ''}{v.cveId ? ` · ${v.cveId}` : ''}
                                    </p>
                                </div>
                            </div>
                        );
                    })}
                </GlassCard>
            </div>

            <div className="srv-grid-2" style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 18 }}>
                <ReconLog vulns={vulns} scan={scan} />
                <ThreatIntelPanel attackMap={attackMap} />
            </div>

            <GlassCard style={{ padding: 22 }}>
                <SectionTitle title="Scan Details" sub="Assessment metadata" />
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 12 }}>
                    {[
                        ['Target', target],
                        ['Hostname', scan?.hostname || (scan?.asset?.target || 'N/A')],
                        ['Assessment Date', scanDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })],
                        ['Duration', scanDuration ? `${scanDuration} min` : 'N/A'],
                        ['Report ID', scan?.id ? String(scan.id).slice(0, 8).toUpperCase() : 'N/A'],
                        ['Health Grade', scan?.healthGrade || risk.grade || 'N/A'],
                    ].map(([label, value]) => (
                        <div key={label} style={{ background: '#F8FAFC', border: '1px solid #E8EDF2', borderRadius: 10, padding: '11px 14px' }}>
                            <p style={{ fontSize: 12, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', margin: '0 0 5px', fontFamily: MONO }}>{label}</p>
                            <p style={{ fontSize: 12.5, fontWeight: 600, color: '#334155', margin: 0, wordBreak: 'break-all', fontFamily: FONT }}>{value}</p>
                        </div>
                    ))}
                </div>
            </GlassCard>
        </div>
    );
}

function FindingsTab({ vulns, counts, total, mode }) {
    const [query, setQuery] = useState('');
    const [severity, setSeverity] = useState('all');
    const [status, setStatus] = useState('all');
    const [sortBy, setSortBy] = useState('severity');
    const [expandedId, setExpandedId] = useState(null);

    const q = query.trim().toLowerCase();
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    let rows = vulns.filter(v => {
        if (severity !== 'all' && v.severity !== severity) return false;
        if (mode === 'auth' && status !== 'all' && (v.status || 'open') !== status) return false;
        if (q && !`${v.title} ${v.category || ''} ${v.cveId || ''} ${v.description || ''}`.toLowerCase().includes(q)) return false;
        return true;
    });
    rows = [...rows].sort((a, b) => {
        if (sortBy === 'severity') return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5);
        if (sortBy === 'cvss') return (Number(b.cvssScore) || 0) - (Number(a.cvssScore) || 0);
        if (sortBy === 'title') return (a.title || '').localeCompare(b.title || '');
        return 0;
    });

    return (
        <div>
            {/* Toolbar */}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }}>
                        <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                    <input
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                        placeholder="Search findings, CVEs, categories…"
                        style={{
                            width: '100%', padding: '10px 12px 10px 36px', borderRadius: 10, fontSize: 13,
                            background: '#F8FAFC', border: '1px solid #E2E8F0', color: '#1e293b',
                            outline: 'none', fontFamily: FONT, transition: 'border-color .15s, box-shadow .15s',
                        }}
                        onFocus={e => { e.currentTarget.style.borderColor = 'rgba(6,182,212,0.5)'; e.currentTarget.style.boxShadow = '0 0 0 3px rgba(6,182,212,0.12)'; }}
                        onBlur={e => { e.currentTarget.style.borderColor = '#E2E8F0'; e.currentTarget.style.boxShadow = 'none'; }}
                    />
                </div>
                <select value={sortBy} onChange={e => setSortBy(e.target.value)}
                    style={{ padding: '10px 12px', borderRadius: 10, fontSize: 13, background: '#F8FAFC', border: '1px solid #E2E8F0', color: '#475569', outline: 'none', cursor: 'pointer', fontFamily: FONT }}>
                    <option value="severity">Sort: Severity</option>
                    <option value="cvss">Sort: CVSS Score</option>
                    <option value="title">Sort: Title A–Z</option>
                </select>
                {mode === 'auth' && (
                    <select value={status} onChange={e => setStatus(e.target.value)}
                        style={{ padding: '10px 12px', borderRadius: 10, fontSize: 13, background: '#F8FAFC', border: '1px solid #E2E8F0', color: '#475569', outline: 'none', cursor: 'pointer', fontFamily: FONT }}>
                        <option value="all">Status: All</option>
                        {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                )}
            </div>

            {/* Severity filter pills */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 18 }}>
                <button onClick={() => setSeverity('all')} style={{
                    padding: '6px 13px', borderRadius: 999, fontSize: 13, fontWeight: 700, cursor: 'pointer',
                    border: severity === 'all' ? '1px solid rgba(6,182,212,0.5)' : '1px solid #E2E8F0',
                    background: severity === 'all' ? 'rgba(6,182,212,0.14)' : '#F8FAFC',
                    color: severity === 'all' ? '#0E7490' : '#475569', fontFamily: FONT, transition: 'all .15s',
                }}>
                    All ({total})
                </button>
                {SEV_ORDER.map(k => {
                    const cfg = SEV_CONFIG[k];
                    const count = counts[k] || 0;
                    const active = severity === k;
                    return (
                        <button key={k} onClick={() => setSeverity(active ? 'all' : k)} style={{
                            display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 13px', borderRadius: 999, fontSize: 13, fontWeight: 700, cursor: 'pointer',
                            border: active ? `1px solid ${cfg.border}` : '1px solid #E2E8F0',
                            background: active ? cfg.bg : '#F8FAFC',
                            color: active ? cfg.text : '#475569', fontFamily: FONT, transition: 'all .15s',
                        }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, boxShadow: active ? `0 0 6px ${cfg.color}` : 'none' }} />
                            {cfg.label} ({count})
                        </button>
                    );
                })}
            </div>

            {rows.length === 0 ? (
                <GlassCard style={{ padding: 48, textAlign: 'center' }} hover={false}>
                    <div style={{ width: 46, height: 46, borderRadius: 13, background: '#F8FAFC', border: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 14px', color: '#64748b' }}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
                    </div>
                    <p style={{ fontSize: 14, fontWeight: 600, color: '#334155', margin: '0 0 4px', fontFamily: FONT }}>
                        {vulns.length === 0 ? 'No vulnerabilities detected in this scan.' : 'No results match your current filters.'}
                    </p>
                    {vulns.length === 0 && <p style={{ fontSize: 12, color: '#64748b', margin: 0, fontFamily: FONT }}>The target passed the tested security checks — this is a healthy result.</p>}
                </GlassCard>
            ) : (
                rows.map((v, i) => (
                    <FindingRow
                        key={v.id || i}
                        vuln={v}
                        index={i}
                        expanded={expandedId === (v.id ?? i)}
                        onToggle={() => setExpandedId(expandedId === (v.id ?? i) ? null : (v.id ?? i))}
                        mode={mode}
                    />
                ))
            )}

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14, gap: 10, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 13, color: '#475569', fontFamily: MONO }}>
                    SHOWING {rows.length} OF {vulns.length} FINDINGS
                </span>
                <span style={{ fontSize: 13, color: '#475569', fontFamily: MONO }}>
                    SORTED BY {sortBy.toUpperCase()}
                </span>
            </div>
        </div>
    );
}

function MitreTab({ vulns, scan }) {
    // Always computed client-side so the public and authenticated flows render
    // byte-identical kill chains (no dependency on which API shape is used).
    const attackMap = useMemo(() => buildAttackMap(vulns), [vulns]);
    const techs = attackMap?.techniques || [];
    const totalTechniques = attackMap?.totalTechniques ?? techs.length;
    const phases = attackMap?.phases || [];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <GlassCard style={{ padding: 20 }} hover={false}>
                <SectionTitle
                    title="MITRE ATT&CK® Kill Chain"
                    sub={`Attack-path model across ${phases.length} of 14 tactics · ${totalTechniques} technique${totalTechniques === 1 ? '' : 's'} mapped`}
                    accent="#0891B2"
                />
                {/* MITRE ATT&CK Phase Visualization */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10, marginTop: 12 }}>
                    {phases.length === 0 ? (
                        <p style={{ padding: 32, textAlign: 'center', fontSize: 13, color: '#64748b', gridColumn: '1 / -1' }}>No ATT&CK phases mapped for this assessment.</p>
                    ) : phases.map((phase, i) => (
                        <div key={i} style={{
                            background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.15)',
                            borderRadius: 12, padding: '14px 12px', textAlign: 'center',
                        }}>
                            <div style={{ fontSize: 20, fontWeight: 800, color: '#0891B2' }}>{phase.count || phase.techniques?.length || 0}</div>
                            <div style={{ fontSize: 13, fontWeight: 600, color: '#94A3B8', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{phase.name || phase.tactic}</div>
                        </div>
                    ))}
                </div>
            </GlassCard>

            <GlassCard style={{ padding: 0 }} hover={false}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid #EEF2F6' }}>
                    <SectionTitle title="Technique Distribution" sub="Mapped techniques ranked by finding count" accent="#0891B2" style={{ marginBottom: 0 }} />
                </div>
                {techs.length === 0 ? (
                    <p style={{ padding: 32, textAlign: 'center', fontSize: 13, color: '#64748b', fontFamily: FONT }}>No MITRE ATT&CK techniques were mapped for this assessment.</p>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ borderBottom: '1px solid #EEF2F6', background: '#FAFBFC' }}>
                                    {['Technique ID', 'Technique Name', 'Tactic', 'Findings'].map(h => (
                                        <th key={h} style={{ padding: '12px 18px', fontSize: 12.5, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', textAlign: 'left', fontFamily: MONO, whiteSpace: 'nowrap' }}>{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {techs.map((t, i) => (
                                    <tr key={t.id} className="srv-row" style={{ borderBottom: '1px solid #EEF2F6' }}>
                                        <td style={{ padding: '12px 18px', fontFamily: MONO, fontWeight: 700, fontSize: 12, color: '#0891B2', whiteSpace: 'nowrap' }}>
                                            <a href={`https://attack.mitre.org/techniques/${t.id}/`} target="_blank" rel="noopener noreferrer" style={{ color: '#0891B2', textDecoration: 'none' }}>{t.id} ↗</a>
                                        </td>
                                        <td style={{ padding: '12px 18px', fontSize: 13, fontWeight: 600, color: '#1e293b', fontFamily: FONT }}>{t.name}</td>
                                        <td style={{ padding: '12px 18px', fontSize: 12, color: '#475569', fontFamily: FONT }}>{t.tactic}</td>
                                        <td style={{ padding: '12px 18px' }}>
                                            <span style={{ fontSize: 13, fontWeight: 800, color: t.count >= 5 ? '#dc2626' : t.count >= 2 ? '#ea580c' : '#475569', fontFamily: MONO, background: '#F1F5F9', border: '1px solid #E2E8F0', borderRadius: 6, padding: '3px 10px' }}>{t.count}</span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
                <p style={{ padding: '0 20px 16px', margin: '12px 0 0', fontSize: 12.5, color: '#475569', fontFamily: FONT }}>
                    Mappings are correlational and derived from finding characteristics. Technique references: <a href="https://attack.mitre.org/techniques/" target="_blank" rel="noopener noreferrer" style={{ color: '#0891B2' }}>attack.mitre.org/techniques</a>
                </p>
            </GlassCard>
        </div>
    );
}

function ComplianceTab({ vulns, counts, scan }) {
    const frameworks = [
        { name: 'OWASP Top 10 (2021)', status: counts.critical > 2 ? 'Critical' : counts.high > 3 ? 'High' : counts.medium > 0 ? 'Attention' : 'Compliant', color: counts.critical > 2 ? '#dc2626' : counts.high > 3 ? '#ea580c' : counts.medium > 0 ? '#ca8a04' : '#16a34a' },
        { name: 'PCI-DSS 4.0', status: counts.critical > 0 ? 'Non-Conformant' : counts.high > 0 ? 'Observations' : 'Compliant', color: counts.critical > 0 ? '#dc2626' : counts.high > 0 ? '#ea580c' : '#16a34a' },
        { name: 'ISO/IEC 27001', status: counts.critical > 0 ? 'Non-Conformant' : counts.high > 0 ? 'Observations' : counts.medium > 0 ? 'Minor Findings' : 'Compliant', color: counts.critical > 0 ? '#dc2626' : counts.high > 0 ? '#ea580c' : counts.medium > 0 ? '#ca8a04' : '#16a34a' },
        { name: 'NIST CSF 2.0', status: counts.critical > 0 ? 'Non-Conformant' : counts.high > 0 ? 'Observations' : 'Compliant', color: counts.critical > 0 ? '#dc2626' : counts.high > 0 ? '#ea580c' : '#16a34a' },
    ];
    const standards = [
        ['OWASP Top 10', 'A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection · A05 Security Misconfiguration · A06 Vulnerable & Outdated Components · A07 Authentication Failures · A09 Logging Failures · A10 SSRF'],
        ['PCI-DSS 4.0', 'Req 6.3 Vulnerability management · Req 11.3 Penetration testing · Req 12.8 Third-party security'],
        ['ISO/IEC 27001', 'A.12.6 Technical vulnerability management · A.14.2 Security in development & support processes'],
        ['NIST CSF 2.0', 'ID.RA Risk assessment · PR.IP Information protection processes · DE.CM Continuous monitoring · RS.MI Mitigations'],
    ];
    const scanners = [
        ['Custom Discovery Engine', 'Same-origin crawler, robots.txt & sitemap parsing, form / parameter discovery, technology detection'],
        ['Passive Detectors', 'Security headers, cookie flags, CORS policy, HTTP methods, information disclosure, directory exposure'],
        ['Active Detectors', 'Reflected XSS (marker + context analysis), SQL injection (error & differential), open redirect, path traversal'],
        ['Evidence & Validation', 'Baseline comparison, controlled verification, response similarity, confidence scoring, deduplication'],
        ['Analysis & Reporting', 'Severity-band risk model, health score, MITRE ATT&CK mapping, remediation engine'],
    ];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <GlassCard style={{ padding: 22 }}>
                <SectionTitle title="Compliance Impact Assessment" sub="Framework posture based on current findings" accent="#16a34a" />
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                    {frameworks.map(f => (
                        <div key={f.name} style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: 12, padding: '15px 16px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                                <p style={{ fontSize: 12.5, fontWeight: 700, color: '#1e293b', margin: 0, fontFamily: FONT }}>{f.name}</p>
                            </div>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, fontWeight: 800, color: f.color, background: `${f.color}12`, border: `1px solid ${f.color}35`, borderRadius: 999, padding: '3px 10px', fontFamily: MONO }}>
                                <span style={{ width: 6, height: 6, borderRadius: '50%', background: f.color, boxShadow: 'none' }} />
                                {f.status.toUpperCase()}
                            </span>
                        </div>
                    ))}
                </div>
            </GlassCard>

            <div className="srv-grid-2" style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 18 }}>
                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Standards Mapping" sub="Control references for audit-ready documentation" />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                        {standards.map(([std, desc]) => (
                            <div key={std} style={{ background: '#F8FAFC', border: '1px solid #E8EDF2', borderRadius: 10, padding: '12px 14px' }}>
                                <p style={{ fontSize: 12, fontWeight: 700, color: '#0E7490', margin: '0 0 4px', fontFamily: FONT }}>{std}</p>
                                <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.6, margin: 0, fontFamily: FONT }}>{desc}</p>
                            </div>
                        ))}
                    </div>
                </GlassCard>

                <GlassCard style={{ padding: 22 }}>
                    <SectionTitle title="Scanners & Methodology" sub="Tools and techniques used in this assessment" />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {scanners.map(([name, desc]) => (
                            <div key={name} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#16a34a', boxShadow: '0 0 7px rgba(34,197,94,0.6)', flexShrink: 0, marginTop: 5 }} />
                                <div>
                                    <p style={{ fontSize: 12, fontWeight: 700, color: '#1e293b', margin: 0, fontFamily: FONT }}>{name}</p>
                                    <p style={{ fontSize: 13, color: '#64748b', margin: '2px 0 0', lineHeight: 1.5, fontFamily: FONT }}>{desc}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                    <div style={{ marginTop: 16, padding: '13px 14px', background: '#FAFBFC', border: '1px dashed #E2E8F0', borderRadius: 10 }}>
                        <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, margin: 0, fontFamily: FONT }}>
                            Findings were scored using CVSS v3.1 and mapped to MITRE ATT&CK v19.1. This report is intended for authorized security assessments of systems you own or have written permission to test.
                        </p>
                    </div>
                </GlassCard>
            </div>
        </div>
    );
}

/* ─── Header actions ─────────────────────────────────────────────────────── */
function ExportActions({ formats, onExport, busy }) {
    const meta = {
        pdf: { label: 'PDF Report', color: '#dc2626', icon: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg> },
        html: { label: 'HTML', color: '#0891B2', icon: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg> },
        xml: { label: 'XML', color: '#ca8a04', icon: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg> },
        json: { label: 'JSON', color: '#2563eb', icon: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg> },
        csv: { label: 'CSV', color: '#059669', icon: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" /></svg> },
    };
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {formats.map(f => {
                const m = meta[f] || meta.json;
                return (
                    <ConsoleButton key={f} primary={f === 'pdf'} disabled={!!busy} onClick={() => onExport(f)} style={{ padding: '9px 14px', fontSize: 12 }}>
                        {busy === f
                            ? <span style={{ width: 12, height: 12, border: '2px solid rgba(255,255,255,0.4)', borderTopColor: '#fff', borderRadius: '50%', animation: 'srvSpin .8s linear infinite', display: 'inline-block', flexShrink: 0 }} />
                            : m.icon}
                        {busy === f ? 'Exporting…' : m.label}
                    </ConsoleButton>
                );
            })}
        </div>
    );
}

/* ─── Main component ─────────────────────────────────────────────────────── */
export default function ScanReportView({
    scan,
    vulns = [],
    mode = 'public',
    exportFormats = [],
    onExport = () => {},
    busy = '',
    onBack,
    backLabel = 'Back',
    kicker = 'Vulnerability Assessment // Report',
}) {
    const [tab, setTab] = useState('overview');

    const counts = useMemo(() => normalizeCounts(scan, vulns), [scan, vulns]);
    const total = SEV_ORDER.reduce((a, k) => a + (counts[k] || 0), 0);
    const risk = useMemo(() => computeRisk(scan, counts, vulns), [scan, counts, vulns]);
    const scanDate = scan?.createdAt ? new Date(scan.createdAt) : new Date();
    const scanDuration = scan?.completedAt && scan?.startedAt
        ? Math.max(1, Math.round((new Date(scan.completedAt) - new Date(scan.startedAt)) / 60000)) : null;
    const target = scan?.asset?.target || scan?.targetUrl || scan?.hostname || 'Target';
    const scannerType = (scan?.scannerType || 'full').toUpperCase();

    const tabs = [
        { key: 'overview', label: 'Overview' },
        { key: 'findings', label: 'Findings', count: total },
        { key: 'mitre', label: 'MITRE ATT&CK' },
        { key: 'compliance', label: 'Compliance' },
    ];

    const kpiIcons = {
        total: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /></svg>,
        critical: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>,
        high: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 20V10M12 20V4M6 20v-6" /></svg>,
        medium: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 20V10M12 20V4M6 20v-6" /></svg>,
        low: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 20h16M12 4v12M6 12l6 6 6-6" /></svg>,
        info: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" /></svg>,
        risk: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /></svg>,
    };

    return (
        <div style={{ fontFamily: FONT, color: '#1e293b', animation: 'srvFadeUp .35s ease' }}>
            <style>{GLOBAL_STYLES}</style>

            {/* Back */}
            {onBack && (
                <button onClick={onBack} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 12.5, color: '#64748b', background: '#F8FAFC',
                    border: '1px solid #E2E8F0', cursor: 'pointer', marginBottom: 22, padding: '7px 14px', borderRadius: 9,
                    transition: 'all .15s', fontFamily: FONT,
                }}
                    onMouseEnter={e => { e.currentTarget.style.color = '#1e293b'; e.currentTarget.style.borderColor = 'rgba(6,182,212,0.35)'; e.currentTarget.style.background = 'rgba(6,182,212,0.08)'; }}
                    onMouseLeave={e => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.borderColor = '#E2E8F0'; e.currentTarget.style.background = '#F8FAFC'; }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6" /></svg>
                    {backLabel}
                </button>
            )}

            {/* Header */}
            <div style={{
                position: 'relative', overflow: 'hidden', borderRadius: 18, padding: '26px 28px',
                background: 'linear-gradient(135deg, #F0F9FF 0%, #FFFFFF 60%, #F8FAFC 100%)',
                border: '1px solid rgba(6,182,212,0.18)', marginBottom: 20,
                boxShadow: '0 1px 3px rgba(15,23,42,0.08)',
            }}>
                <div style={{ position: 'absolute', top: -80, right: -60, width: 320, height: 320, borderRadius: '50%', background: 'radial-gradient(circle, rgba(6,182,212,0.14) 0%, transparent 70%)', pointerEvents: 'none' }} />
                <div style={{ position: 'absolute', bottom: -100, left: '30%', width: 280, height: 280, borderRadius: '50%', background: 'radial-gradient(circle, rgba(239,68,68,0.05) 0%, transparent 70%)', pointerEvents: 'none' }} />
                <div style={{ position: 'relative', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 20, flexWrap: 'wrap' }}>
                    <div style={{ minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#0891B2', boxShadow: '0 0 10px #0891B2', flexShrink: 0, animation: 'srvPulse 2.4s ease-in-out infinite' }} />
                            <span style={{ fontSize: 12.5, fontWeight: 700, color: '#0E7490', textTransform: 'uppercase', letterSpacing: '0.18em', fontFamily: MONO }}>{kicker}</span>
                        </div>
                        <h1 style={{ fontSize: 'clamp(20px, 3vw, 30px)', fontWeight: 800, color: '#0f172a', margin: 0, letterSpacing: '-0.02em', lineHeight: 1.15, wordBreak: 'break-word', fontFamily: FONT }}>
                            {target}
                        </h1>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginTop: 10, fontFamily: MONO, fontSize: 13, color: '#64748b' }}>
                            <span>{scannerType}{scanDuration ? ` · ${scanDuration} MIN` : ''}</span>
                            <span style={{ color: '#CBD5E1' }}>•</span>
                            <span>{scanDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} {scanDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}</span>
                            <span style={{ color: '#CBD5E1' }}>•</span>
                            <span>{total} FINDING{total === 1 ? '' : 'S'}</span>
                        </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 10 }}>
                        <ExportActions formats={exportFormats} onExport={onExport} busy={busy} />
                    </div>
                </div>
            </div>

            {/* Status strip */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                <StatusPill status={scan?.status || 'completed'} />
                {scan?.id && (
                    <span style={{ fontSize: 13, color: '#64748b', fontFamily: MONO }}>
                        REPORT {String(scan.id).slice(0, 8).toUpperCase()}
                    </span>
                )}
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 800, color: risk.rating.color, fontFamily: MONO }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: risk.rating.color, boxShadow: 'none' }} />
                    THREAT LEVEL: {risk.rating.label}
                </span>
                <span style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#64748b', fontFamily: MONO }}>
                    <span style={{ color: '#475569' }}>RISK</span>
                    <strong style={{ color: risk.riskScore >= 60 ? '#dc2626' : risk.riskScore >= 30 ? '#ea580c' : risk.riskScore >= 10 ? '#ca8a04' : '#16a34a', fontSize: 15 }}>{risk.riskScore}</strong>
                    <span style={{ color: '#475569' }}>/100</span>
                    <span style={{ width: 1, height: 14, background: '#E2E8F0' }} />
                    <span style={{ color: '#475569' }}>GRADE</span>
                    <strong style={{ color: risk.riskScore >= 60 ? '#dc2626' : risk.riskScore >= 30 ? '#ea580c' : '#16a34a' }}>{risk.grade}</strong>
                </span>
            </div>

            {/* KPI cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 12, marginBottom: 20 }}>
                {[
                    { label: 'Total Findings', value: total, accent: '#0891B2', icon: kpiIcons.total, sub: 'All severities' },
                    { label: 'Critical', value: counts.critical || 0, accent: '#dc2626', icon: kpiIcons.critical, sub: 'P1 · 0–24h SLA' },
                    { label: 'High', value: counts.high || 0, accent: '#ea580c', icon: kpiIcons.high, sub: 'P2 · 1–7d SLA' },
                    { label: 'Medium', value: counts.medium || 0, accent: '#ca8a04', icon: kpiIcons.medium, sub: 'P3 · 7–30d SLA' },
                    { label: 'Low', value: counts.low || 0, accent: '#2563eb', icon: kpiIcons.low, sub: 'P4 · 30–90d SLA' },
                    { label: 'Info', value: counts.info || 0, accent: '#64748b', icon: kpiIcons.info, sub: 'P5 · Informational' },
                    { label: 'Risk Score', value: risk.riskScore, accent: risk.riskScore >= 60 ? '#dc2626' : risk.riskScore >= 30 ? '#ea580c' : '#16a34a', icon: kpiIcons.risk, sub: `Grade ${risk.grade}` },
                ].map((k, i) => (
                    <div key={k.label} style={{
                        background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 14, padding: '15px 17px',
                        transition: 'border-color .2s, transform .2s', animation: `srvFadeUp .35s ease ${i * 50}ms both`,
                    }}
                        onMouseEnter={e => { e.currentTarget.style.borderColor = `${k.accent}55`; e.currentTarget.style.transform = 'translateY(-2px)'; }}
                        onMouseLeave={e => { e.currentTarget.style.borderColor = '#E2E8F0'; e.currentTarget.style.transform = 'none'; }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                            <div style={{ width: 34, height: 34, borderRadius: 10, background: `${k.accent}16`, border: `1px solid ${k.accent}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: k.accent, boxShadow: 'none' }}>{k.icon}</div>
                            <span style={{ fontSize: 12, fontWeight: 700, color: '#475569', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: MONO }}>{k.sub}</span>
                        </div>
                        <p style={{ fontSize: 13, fontWeight: 600, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.07em', margin: 0, fontFamily: FONT }}>{k.label}</p>
                        <p style={{ fontSize: 30, fontWeight: 800, color: k.accent === '#0891B2' ? '#0f172a' : k.accent, margin: '4px 0 0', lineHeight: 1.1, fontVariantNumeric: 'tabular-nums', fontFamily: FONT }}>
                            <AnimatedCount value={k.value} />
                        </p>
                        <div style={{ height: 3, borderRadius: 2, background: '#EEF2F6', marginTop: 12, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: '100%', background: `linear-gradient(90deg, ${k.accent}66, ${k.accent})`, borderRadius: 2, boxShadow: 'none' }} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <ConsoleTabs tabs={tabs} active={tab} onChange={setTab} />

            {tab === 'overview' && <OverviewTab scan={scan} vulns={vulns} counts={counts} total={total} risk={risk} scanDate={scanDate} scanDuration={scanDuration} />}
            {tab === 'findings' && <FindingsTab vulns={vulns} counts={counts} total={total} mode={mode} />}
            {tab === 'mitre' && <MitreTab vulns={vulns} scan={scan} />}
            {tab === 'compliance' && <ComplianceTab vulns={vulns} counts={counts} scan={scan} />}

            {/* Footer */}
            <div style={{ marginTop: 28, paddingTop: 18, borderTop: '1px solid #EEF2F6', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 13, color: '#475569', fontFamily: MONO }}>
                    VULNSCAN PRO · CONFIDENTIAL · {scanDate.toLocaleDateString('en-GB', { year: 'numeric' })}
                </span>
                <span style={{ fontSize: 13, color: '#475569', fontFamily: MONO }}>
                    REPORT {scan?.id ? String(scan.id).slice(0, 8).toUpperCase() : '—'} · SEVERITIES C: {counts.critical || 0} H: {counts.high || 0} M: {counts.medium || 0} L: {counts.low || 0} I: {counts.info || 0}
                </span>
            </div>
        </div>
    );
}
