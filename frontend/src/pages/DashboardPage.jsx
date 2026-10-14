import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardAPI, scanAPI } from '../services/api';
import { Spinner } from '../components/ui';
import { computeRisk } from '../components/ScanReportView';
import {
    CONSOLE, SEV_CONFIG, SEV_ORDER, AnimatedCount, GlassCard, SectionTitle,
    ConsoleHeader, ConsoleButton, KpiCard, FindingChip, StatusPill, ConsoleEmpty, ErrorBanner,
} from '../components/console';

/* ─── Grade badge (colors match the report grading model) ─────────────────── */
const GRADE_COLORS = { 'A+': '#16a34a', A: '#16a34a', B: '#0891b2', C: '#ca8a04', D: '#ea580c', F: '#dc2626' };
const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];

function GradeBadge({ grade, size = 'md' }) {
    const g = String(grade || '—').toUpperCase();
    const color = GRADE_COLORS[g] || '#64748b';
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800,
            fontFamily: CONSOLE.MONO, color, background: `${color}14`, border: `1px solid ${color}40`,
            borderRadius: size === 'lg' ? 10 : 7, padding: size === 'lg' ? '6px 18px' : '2px 8px',
            fontSize: size === 'lg' ? 15 : 11, letterSpacing: '0.06em', lineHeight: 1.2, whiteSpace: 'nowrap',
        }}>
            {g}
        </span>
    );
}

// ─── Risk gauge (semicircle) — driven by the SHARED risk model ──────────────
// (computeRisk from ScanReportView) so the score, grade and threat level
// shown here are identical to the scan report grading.
function RiskGauge({ risk }) {
    const clamped = Math.max(0, Math.min(100, Number(risk?.riskScore) || 0));
    const stroke = 13, r = 58;
    const circ = Math.PI * r;
    const filled = (clamped / 100) * circ;
    const color = risk?.rating?.color || '#16a34a';
    const arc = `M 12 72 A ${r} ${r} 0 0 1 ${12 + 2 * r} 72`;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }} role="img" aria-label={`Risk score ${clamped} out of 100, grade ${risk?.grade || 'N/A'}`}>
            <svg width="140" height="86" style={{ overflow: 'visible' }} aria-hidden="true">
                <path d={arc} stroke="#E2E8F0" strokeWidth={stroke} fill="none" strokeLinecap="round" />
                <path d={arc} stroke={color} strokeWidth={stroke} fill="none" strokeLinecap="round"
                    strokeDasharray={`${filled} ${circ}`} style={{ transition: 'stroke-dasharray 1.2s ease', filter: 'none' }} />
                <text x="70" y="60" textAnchor="middle" fontSize={34} fontWeight={800} fill="#0f172a" fontFamily={CONSOLE.FONT}>{clamped}</text>
                <text x="70" y="76" textAnchor="middle" fontSize={8.5} fontWeight={700} fill="#64748b" letterSpacing="0.14em" fontFamily={CONSOLE.MONO}>RISK SCORE / 100</text>
            </svg>
            <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                <GradeBadge grade={risk?.grade} size="lg" />
                <span style={{
                    padding: '6px 14px', borderRadius: 999, fontSize: 13, fontWeight: 800,
                    color, background: `${color}12`, border: `1px solid ${color}35`, letterSpacing: '0.08em', fontFamily: CONSOLE.MONO,
                }}>
                    {risk?.rating?.label || 'SECURE'} RISK
                </span>
            </div>
        </div>
    );
}

// ─── Vulnerability trend chart ───────────────────────────────────────────────
function TrendChart({ recentScans }) {
    const last7 = [...(recentScans || [])].slice(0, 7).reverse();
    if (!last7.length) return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, height: 120 }}>
            <p style={{ fontSize: 13, color: '#64748b', fontFamily: CONSOLE.FONT, margin: 0 }}>No scan data yet</p>
            <p style={{ fontSize: 13, color: '#475569', fontFamily: CONSOLE.FONT, margin: 0 }}>Run a scan to see the trend</p>
        </div>
    );

    const data = last7.map(s => ({
        label: new Date(s.createdAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }),
        critical: s.severitySummary?.critical || 0,
        high: s.severitySummary?.high || 0,
        medium: s.severitySummary?.medium || 0,
    }));

    const maxVal = Math.max(...data.flatMap(d => [d.critical + d.high + d.medium]), 1);
    const chartH = 100;
    const chartW = 400;
    const barW = Math.max(20, (chartW / data.length) - 8);

    return (
        <svg viewBox={`0 0 ${chartW} ${chartH + 24}`} style={{ width: '100%', height: 'auto' }} role="img" aria-label="Findings per scan, last scans">
            {[0.25, 0.5, 0.75].map(f => (
                <line key={f} x1="0" y1={chartH * f} x2={chartW} y2={chartH * f} stroke="#EEF2F6" strokeWidth="1" strokeDasharray="4 6" />
            ))}
            {data.map((d, i) => {
                const x = (i / data.length) * chartW + 4;
                const scale = (v) => (v / maxVal) * chartH;
                let yPos = chartH;
                return (
                    <g key={i}>
                        {[{ v: d.medium, c: SEV_CONFIG.medium.color }, { v: d.high, c: SEV_CONFIG.high.color }, { v: d.critical, c: SEV_CONFIG.critical.color }].map(({ v, c }) => {
                            if (!v) return null;
                            const h = scale(v);
                            yPos -= h;
                            return <rect key={c} x={x} y={yPos} width={barW - 4} height={h} fill={c} rx="2" opacity="0.85" />;
                        })}
                        <text x={x + (barW - 4) / 2} y={chartH + 16} textAnchor="middle" fill="#475569" fontSize="9">{d.label}</text>
                    </g>
                );
            })}
        </svg>
    );
}

// ─── Severity row ────────────────────────────────────────────────────────────
function SeverityRowInner({ cfg, count, pct }) {
    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: cfg.color, boxShadow: count > 0 ? `0 0 8px ${cfg.color}` : 'none', flexShrink: 0 }} aria-hidden="true" />
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: '#334155', fontFamily: CONSOLE.FONT }}>{cfg.label}</span>
                </div>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <span style={{ fontSize: 13, color: '#475569', fontFamily: CONSOLE.MONO }}>{pct}%</span>
                    <span style={{ fontSize: 14, fontWeight: 800, minWidth: 22, textAlign: 'right', color: count > 0 ? cfg.color : '#CBD5E1', fontVariantNumeric: 'tabular-nums', fontFamily: CONSOLE.MONO }}>{count}</span>
                </div>
            </div>
            <div style={{ height: 6, borderRadius: 4, background: '#EEF2F6', overflow: 'hidden' }} role="img" aria-label={`${cfg.label}: ${count} findings, ${pct}%`}>
                <div style={{
                    height: '100%', borderRadius: 4, transition: 'width .7s ease',
                    width: `${Math.max(count > 0 ? 4 : 0, pct)}%`,
                    background: `linear-gradient(90deg, ${cfg.color}88, ${cfg.color})`,
                    boxShadow: count > 0 ? `0 0 8px ${cfg.color}55` : 'none',
                }} />
            </div>
        </div>
    );
}

// ─── Main Dashboard ──────────────────────────────────────────────────────────
export default function DashboardPage() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState('');
    const [modelInfo, setModelInfo] = useState(null);
    const navigate = useNavigate();

    const fetchData = (isRetry = false) => {
        if (isRetry) setLoading(true);
        return dashboardAPI.getStats()
            .then(r => { setStats(r.data.data); setFetchError(''); })
            .catch(err => {
                // Keep stale data on refresh errors; only surface when we have nothing
                if (!stats) setFetchError(err.response?.data?.error?.message || 'Could not load dashboard data.');
            })
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchData();
        const id = setInterval(() => fetchData(), 20000);
        return () => clearInterval(id);
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    // AI/ML engine status — derived from real classification data on the most
    // recent completed scan. Never invents a model or accuracy figures.
    useEffect(() => {
        const latest = (stats?.recentScans || []).find(s => s.status === 'completed');
        if (!latest) { setModelInfo(null); return; }
        let cancelled = false;
        scanAPI.getVulnerabilities(latest.id, { limit: 1 })
            .then(r => {
                if (cancelled) return;
                const v = (r.data.data || [])[0];
                const ml = v?.mlClassification || v?.ml_classification;
                if (!ml) setModelInfo({ mode: 'unknown' });
                else if (ml.classification_method === 'ml_random_forest') {
                    setModelInfo({ mode: 'ml', version: ml.model_version, schema: ml.schema_version, threshold: ml.threshold });
                } else {
                    setModelInfo({ mode: 'fallback', threshold: ml.threshold, note: ml.note });
                }
            })
            .catch(() => { if (!cancelled) setModelInfo({ mode: 'unknown' }); });
        return () => { cancelled = true; };
    }, [stats?.recentScans?.length]);

    if (loading && !stats) return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '50vh', gap: 14 }}>
            <Spinner size={38} />
            <p style={{ fontSize: 12, color: '#64748b', letterSpacing: '0.08em', fontFamily: CONSOLE.MONO }}>INITIALIZING CONSOLE…</p>
        </div>
    );

    if (fetchError && !stats) {
        return (
            <div style={{ maxWidth: 560, margin: '60px auto' }}>
                <GlassCard hover={false} style={{ padding: 0 }}>
                    <ErrorBanner message={fetchError} style={{ margin: 0, border: 'none', borderRadius: '16px 16px 0 0' }} />
                    <div style={{ padding: 20, display: 'flex', justifyContent: 'flex-end' }}>
                        <ConsoleButton primary={false} onClick={() => fetchData(true)}>Try again</ConsoleButton>
                    </div>
                </GlassCard>
            </div>
        );
    }

    const sev = stats?.severityDistribution || {};
    const totalFindings = Object.values(sev).reduce((a, b) => a + b, 0);
    const recentScans = stats?.recentScans || [];
    const assets = stats?.assets || [];

    // Shared risk model — the exact same computeRisk used by the scan report UI,
    // so the dashboard grade/threat-level always match the report grading.
    // (Aggregate severity counts only — the per-vuln CVSS bonus isn't available
    // in the dashboard rollup, so this is the severity-weighted core of the model.)
    const risk = computeRisk(null, sev, []);
    const riskScore = risk.riskScore;

    // Grade distribution across assets (grades written by the worker using the
    // shared risk model, so they match each asset's latest scan report).
    const gradeDist = {};
    assets.forEach(a => { const g = a.healthGrade || '—'; gradeDist[g] = (gradeDist[g] || 0) + 1; });

    const completedScans = recentScans.filter(s => s.status === 'completed' && s.completedAt && s.startedAt);
    // Honest duration average — only real completed scans count; '—' when none.
    const avgDuration = completedScans.length > 0 ? Math.round(
        completedScans.reduce((acc, s) => acc + (new Date(s.completedAt) - new Date(s.startedAt)) / 60000, 0) / completedScans.length
    ) : null;

    const runningCount = recentScans.filter(s => ['running', 'queued'].includes(s.status)).length;

    const assetGradeMap = {};
    assets.forEach(a => {
        if (a.target) assetGradeMap[a.target] = a.healthGrade;
        if (a.name) assetGradeMap[a.name] = a.healthGrade;
    });
    const assetVulnMap = {};
    recentScans.forEach(s => {
        const key = s.asset?.target || s.asset?.name;
        if (key) {
            if (!assetVulnMap[key]) assetVulnMap[key] = { name: key, critical: 0, high: 0, total: 0 };
            assetVulnMap[key].critical += s.severitySummary?.critical || 0;
            assetVulnMap[key].high += s.severitySummary?.high || 0;
            assetVulnMap[key].total += s.totalVulnerabilities || 0;
            assetVulnMap[key].healthGrade = assetGradeMap[key] || null;
        }
    });
    const topAssets = Object.values(assetVulnMap).sort((a, b) => b.critical * 10 + b.high - (a.critical * 10 + a.high)).slice(0, 5);

    return (
        <div style={{ animation: 'fadeIn .35s ease' }}>
            <ConsoleHeader
                kicker="Operations // Security Posture"
                title="Security Overview"
                sub="Risk score, findings and scan activity across your targets"
                accent={CONSOLE.CYAN}
                actions={
                    <ConsoleButton onClick={() => navigate('/app/scans')}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                        New Scan
                    </ConsoleButton>
                }
            />

            {/* Metric cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 14, marginBottom: 18 }}>
                <KpiCard
                    label="Total Scans" value={stats?.totalScans || 0} sub="All time" accent="#0891B2" delay={0}
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>}
                />
                <KpiCard
                    label="Targets" value={stats?.totalAssets || 0} sub="Registered" accent="#0E7490" delay={60}
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" /></svg>}
                />
                <KpiCard
                    label="Total Findings" value={totalFindings} sub={`${sev.critical || 0} critical`}
                    accent={totalFindings > 0 ? (sev.critical > 0 ? '#dc2626' : '#ca8a04') : '#16a34a'} delay={120}
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /></svg>}
                />
                <KpiCard
                    label="Avg Scan Time" value={avgDuration !== null ? <AnimatedCount value={avgDuration} /> : '—'}
                    sub={avgDuration !== null ? 'Minutes per completed scan' : 'No completed scans yet'} accent="#ea580c" delay={180}
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>}
                />
            </div>

            {/* Running scan strip — only when scans are actually in flight */}
            {runningCount > 0 && (
                <GlassCard style={{ padding: '13px 18px', marginBottom: 18, display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }} hover={false}>
                    <span className="w-2 h-2 rounded-full animate-pulse-dot" style={{ background: '#0891B2', display: 'inline-block' }} aria-hidden="true" />
                    <p style={{ fontSize: 12.5, fontWeight: 600, color: '#1e293b', margin: 0, fontFamily: CONSOLE.FONT, flex: 1, minWidth: 180 }}>
                        {runningCount} scan{runningCount !== 1 ? 's' : ''} in progress
                    </p>
                    <ConsoleButton primary={false} onClick={() => navigate('/app/scans')} style={{ padding: '6px 14px', fontSize: 12 }}>
                        View progress
                    </ConsoleButton>
                </GlassCard>
            )}

            {/* AI/ML engine status strip — honest, data-driven */}
            {modelInfo && (
                <GlassCard style={{ padding: '13px 18px', marginBottom: 18, display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }} hover={false}>
                    <div style={{
                        width: 34, height: 34, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.3)', color: '#0891B2',
                    }} aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a5 5 0 0 1 5 5c0 2.4-1.7 4.4-4 4.9V14h2a1 1 0 0 1 1 1v2h1a1 1 0 0 1 1 1v3H7v-3a1 1 0 0 1 1-1h1v-2a1 1 0 0 1 1-1h2v-2.1c-2.3-.5-4-2.5-4-4.9a5 5 0 0 1 5-5z" /></svg>
                    </div>
                    <div style={{ flex: 1, minWidth: 180 }}>
                        <p style={{ fontSize: 12, fontWeight: 700, color: '#1e293b', margin: 0, fontFamily: CONSOLE.FONT }}>
                            AI/ML Classification —{' '}
                            {modelInfo.mode === 'ml' && <span style={{ color: '#16a34a' }}>Random Forest active</span>}
                            {modelInfo.mode === 'fallback' && <span style={{ color: '#ca8a04' }}>Rule-based fallback</span>}
                            {modelInfo.mode === 'unknown' && <span style={{ color: '#475569' }}>No classification data yet</span>}
                        </p>
                        <p style={{ fontSize: 13, color: '#64748b', margin: '2px 0 0', fontFamily: CONSOLE.MONO }}>
                            {modelInfo.mode === 'ml' && `model ${modelInfo.version} · schema v${modelInfo.schema} · threshold ${modelInfo.threshold}`}
                            {modelInfo.mode === 'fallback' && 'no trained model — evidence-based scoring, all findings flagged for manual review'}
                            {modelInfo.mode === 'unknown' && 'complete a scan to populate classification status'}
                        </p>
                    </div>
                    {modelInfo.mode === 'fallback' && (
                        <span style={{
                            fontSize: 12, fontWeight: 800, padding: '3px 10px', borderRadius: 999, fontFamily: CONSOLE.MONO,
                            color: '#ca8a04', background: 'rgba(251,191,36,0.1)', border: '1px solid rgba(251,191,36,0.35)',
                        }}>UNTRAINED MODEL</span>
                    )}
                    {modelInfo.mode === 'ml' && modelInfo.version && (
                        <span style={{
                            fontSize: 12, fontWeight: 800, padding: '3px 10px', borderRadius: 999, fontFamily: CONSOLE.MONO,
                            color: '#16a34a', background: 'rgba(74,222,128,0.1)', border: '1px solid rgba(74,222,128,0.35)',
                        }}>TRAINED · v{modelInfo.version}</span>
                    )}
                </GlassCard>
            )}

            {/* Middle row */}
            <div className="dash-middle">
                {/* Security grade — shared risk model (matches report grading) */}
                <GlassCard style={{ padding: 22, display: 'flex', flexDirection: 'column', alignItems: 'center' }} hover={false}>
                    <SectionTitle title="Security Grade" sub="Shared risk model — matches report grading" />
                    <RiskGauge risk={risk} />
                    <div style={{ marginTop: 16, width: '100%', borderTop: '1px solid #EEF2F6', paddingTop: 14 }}>
                        <p style={{ fontSize: 13, color: '#64748b', textAlign: 'center', lineHeight: 1.7, fontFamily: CONSOLE.FONT }}>
                            {risk.rating.description}
                        </p>
                    </div>
                    {assets.length > 0 && (
                        <div style={{ marginTop: 14, width: '100%', borderTop: '1px solid #EEF2F6', paddingTop: 14 }}>
                            <p style={{ fontSize: 12, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 10, fontFamily: CONSOLE.MONO }}>
                                Grade Distribution · {assets.length} asset{assets.length !== 1 ? 's' : ''}
                            </p>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                {GRADE_ORDER.map(g => gradeDist[g] ? (
                                    <span key={g} style={{
                                        display: 'inline-flex', alignItems: 'center', gap: 7, padding: '3px 10px', borderRadius: 8,
                                        background: '#F1F5F9', border: '1px solid #E2E8F0',
                                        fontSize: 13, fontFamily: CONSOLE.MONO, fontWeight: 700, color: '#475569',
                                    }}>
                                        <GradeBadge grade={g} /> ×{gradeDist[g]}
                                    </span>
                                ) : null)}
                            </div>
                        </div>
                    )}
                </GlassCard>

                {/* Severity distribution */}
                <GlassCard style={{ padding: 22 }} hover={false}>
                    <SectionTitle title="Severity Distribution" sub="Findings by severity level" accent="#dc2626" />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                        {SEV_ORDER.map(keyName => {
                            const count = sev[keyName] || 0;
                            const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
                            return <SeverityRowInner key={keyName} cfg={SEV_CONFIG[keyName]} count={count} pct={pct} />;
                        })}
                    </div>
                    {totalFindings === 0 && (
                        <p style={{ textAlign: 'center', fontSize: 13, color: '#64748b', marginTop: 16, fontFamily: CONSOLE.FONT }}>
                            {recentScans.some(s => s.status === 'completed')
                                ? 'No vulnerabilities detected'
                                : 'No findings yet — run your first scan'}
                        </p>
                    )}
                </GlassCard>

                {/* Trend */}
                <GlassCard style={{ padding: 22 }} hover={false}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ width: 8, height: 8, borderRadius: 2, background: '#0891B2', boxShadow: 'none' }} aria-hidden="true" />
                            <p style={{ fontSize: 14.5, fontWeight: 700, color: '#1e293b', margin: 0, fontFamily: CONSOLE.FONT }}>Vulnerability Trend</p>
                        </div>
                        <div style={{ display: 'flex', gap: 12, fontSize: 12.5, color: '#64748b', fontFamily: CONSOLE.MONO }}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: SEV_CONFIG.critical.color }} aria-hidden="true" />Crit</span>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: SEV_CONFIG.high.color }} aria-hidden="true" />High</span>
                            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: SEV_CONFIG.medium.color }} aria-hidden="true" />Med</span>
                        </div>
                    </div>
                    <TrendChart recentScans={recentScans} />
                    {recentScans.length > 0 && (
                        <p style={{ fontSize: 13, color: '#475569', textAlign: 'center', marginTop: 12, fontFamily: CONSOLE.MONO }}>LAST {Math.min(recentScans.length, 7)} SCANS</p>
                    )}
                </GlassCard>
            </div>

            {/* Bottom row */}
            <div className="dash-bottom">
                {/* Recent scans */}
                <GlassCard style={{ padding: 0 }} hover={false}>
                    <div style={{ padding: '16px 20px', borderBottom: '1px solid #EEF2F6', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <SectionTitle title="Recent Scans" sub="Latest assessment activity" style={{ marginBottom: 0 }} />
                        <button onClick={() => navigate('/app/scans')} style={{ fontSize: 12, fontWeight: 700, color: '#0891B2', background: 'none', border: 'none', cursor: 'pointer', fontFamily: CONSOLE.FONT, whiteSpace: 'nowrap' }}>View all →</button>
                    </div>
                    {recentScans.length === 0 ? (
                        <ConsoleEmpty
                            title="No scans yet"
                            desc="Launch your first assessment to see live results here."
                            icon={<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>}
                            action={<ConsoleButton onClick={() => navigate('/app/scans')}>Start a Scan</ConsoleButton>}
                        />
                    ) : (
                        recentScans.slice(0, 6).map((scan, i) => (
                            <div key={scan.id} onClick={() => navigate(`/app/scans/${scan.id}`)} role="button" tabIndex={0}
                                onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/app/scans/${scan.id}`); } }}
                                aria-label={`Open scan of ${scan.asset?.target || 'unknown target'}`}
                                style={{
                                    display: 'flex', alignItems: 'center', gap: 14, padding: '13px 20px', cursor: 'pointer',
                                    borderBottom: i < 5 ? '1px solid #EEF2F6' : 'none',
                                    transition: 'background .15s',
                                }}
                                onMouseEnter={e => e.currentTarget.style.background = 'rgba(6,182,212,0.05)'}
                                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                                onFocus={e => e.currentTarget.style.background = 'rgba(6,182,212,0.05)'}
                                onBlur={e => e.currentTarget.style.background = 'transparent'}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: 11, background: 'rgba(6,182,212,0.08)',
                                    border: '1px solid rgba(6,182,212,0.25)', display: 'flex', alignItems: 'center',
                                    justifyContent: 'center', color: '#0891B2', flexShrink: 0,
                                }} aria-hidden="true">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                </div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <p style={{ fontSize: 13, fontWeight: 600, color: '#1e293b', margin: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: CONSOLE.FONT }}>{scan.asset?.target || 'Unknown'}</p>
                                    <p style={{ fontSize: 12.5, color: '#475569', marginTop: 3, textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: CONSOLE.MONO }}>
                                        {scan.scannerType} • {new Date(scan.createdAt).toLocaleDateString()}
                                    </p>
                                </div>
                                <div style={{ display: 'flex', gap: 7, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                    {SEV_ORDER.filter(k => (scan.severitySummary?.[k] || 0) > 0 && k !== 'info').map(k => (
                                        <FindingChip key={k} severity={k} count={scan.severitySummary[k]} />
                                    ))}
                                    <StatusPill status={scan.status} progress={scan.progress} />
                                </div>
                            </div>
                        ))
                    )}
                </GlassCard>

                {/* Top vulnerable assets + quick actions */}
                <GlassCard style={{ padding: 0 }} hover={false}>
                    <div style={{ padding: '16px 20px', borderBottom: '1px solid #EEF2F6' }}>
                        <SectionTitle title="Most Exposed Targets" sub="Ranked by high-severity findings" accent="#dc2626" style={{ marginBottom: 0 }} />
                    </div>
                    {topAssets.length === 0 ? (
                        <div style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b', fontSize: 13, fontFamily: CONSOLE.FONT }}>No asset data yet</div>
                    ) : (
                        <div>
                            {topAssets.map((asset, i) => (
                                <div key={asset.name} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 18px', borderBottom: i < topAssets.length - 1 ? '1px solid #EEF2F6' : 'none' }}>
                                    <div style={{
                                        width: 26, height: 26, borderRadius: 8, display: 'flex', alignItems: 'center',
                                        justifyContent: 'center', fontSize: 13.5, fontWeight: 800, flexShrink: 0, fontFamily: CONSOLE.MONO,
                                        background: i === 0 ? 'rgba(239,68,68,0.14)' : i === 1 ? 'rgba(249,115,22,0.12)' : '#F1F5F9',
                                        color: i === 0 ? '#b91c1c' : i === 1 ? '#c2410c' : '#71717A',
                                        border: `1px solid ${i === 0 ? 'rgba(239,68,68,0.35)' : i === 1 ? 'rgba(249,115,22,0.3)' : '#E2E8F0'}`,
                                    }} aria-hidden="true">
                                        {i + 1}
                                    </div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <p style={{ fontSize: 12, fontWeight: 600, color: '#1e293b', margin: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: CONSOLE.FONT }}>{asset.name}</p>
                                        <p style={{ fontSize: 12.5, color: '#475569', marginTop: 3, fontFamily: CONSOLE.MONO }}>{asset.total} finding{asset.total !== 1 ? 's' : ''}</p>
                                    </div>
                                    <div style={{ display: 'flex', gap: 5, flexShrink: 0, alignItems: 'center' }}>
                                        {asset.healthGrade && <GradeBadge grade={asset.healthGrade} />}
                                        {asset.critical > 0 && <FindingChip severity="critical" count={asset.critical} />}
                                        {asset.high > 0 && <FindingChip severity="high" count={asset.high} />}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    <div style={{ padding: '16px 18px', borderTop: '1px solid #EEF2F6' }}>
                        <p style={{ fontSize: 12, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 12, fontFamily: CONSOLE.MONO }}>Quick Actions</p>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {[
                                { label: 'New Scan', path: '/app/scans', color: '#0891B2' },
                                { label: 'View Reports', path: '/app/reports', color: '#0E7490' },
                                { label: 'Manage Targets', path: '/app/assets', color: '#16a34a' },
                            ].map(a => (
                                <button key={a.label} onClick={() => navigate(a.path)}
                                    style={{
                                        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 10,
                                        textAlign: 'left', cursor: 'pointer', border: `1px solid ${a.color}22`,
                                        background: `${a.color}0d`, color: a.color, fontFamily: CONSOLE.FONT, fontSize: 13, fontWeight: 600,
                                        transition: 'background .15s, border-color .15s',
                                    }}
                                    onMouseEnter={e => { e.currentTarget.style.background = `${a.color}1a`; e.currentTarget.style.borderColor = `${a.color}45`; }}
                                    onMouseLeave={e => { e.currentTarget.style.background = `${a.color}0d`; e.currentTarget.style.borderColor = `${a.color}22`; }}>
                                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: a.color, boxShadow: `0 0 8px ${a.color}90`, flexShrink: 0 }} aria-hidden="true" />
                                    {a.label}
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: 'auto' }} aria-hidden="true"><polyline points="9 18 15 12 9 6" /></svg>
                                </button>
                            ))}
                        </div>
                    </div>
                </GlassCard>
            </div>

        </div>
    );
}
