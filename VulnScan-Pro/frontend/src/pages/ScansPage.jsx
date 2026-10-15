import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanAPI } from '../services/api';
import { useToast, Spinner, Toggle } from '../components/ui';
import {
    CONSOLE, SEV_ORDER, GlassCard, ConsoleHeader, ConsoleButton,
    FindingChip, StatusPill, ConsoleTabs, ConsoleEmpty, ErrorBanner,
} from '../components/console';

/* ─── Scanner info — the one real engine (custom Python scanner) ──────────── */
const SCANNER_INFO = {
    name: 'VulnScan Engine',
    fullName: 'Custom Python scanning engine',
    description: 'Same-origin crawler and endpoint discovery, HTTP header and cookie audits, CORS analysis, XSS, SQL injection, open redirect and path traversal detection — with evidence validation, confidence scoring and MITRE ATT&CK mapping.',
    detects: [
        'Security Headers', 'XSS', 'SQL Injection', 'CORS',
        'Cookie Security', 'Open Redirect', 'Path Traversal',
        'Directory Listing', 'Info Disclosure', 'Discovery',
    ],
};

/* Scan profiles map to engine parameters. Durations reflect the documented
   engine behavior (config.py request budget), not invented figures. */
const SCAN_PROFILES = [
    { id: 'full', name: 'Full Audit', description: 'Discovery, passive checks and active testing across all detector modules.', duration: '2–8 min', icon: 'shield' },
    { id: 'quick', name: 'Quick Scan', description: 'Passive configuration checks: headers, cookies, CORS and information disclosure.', duration: '< 1 min', icon: 'bolt' },
    { id: 'active', name: 'Active Testing', description: 'Adds injection, open redirect and path traversal probes against discovered endpoints.', duration: '3–6 min', icon: 'target' },
];

function ProfileIcon({ name, color = '#0891B2' }) {
    const common = { width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: color, strokeWidth: 1.8, 'aria-hidden': true };
    if (name === 'bolt') return <svg {...common}><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" /></svg>;
    if (name === 'target') return <svg {...common}><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /></svg>;
    return <svg {...common}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
}

/* Basic URL validation — mirrors what the backend SSRF guard will accept. */
function validateTarget(raw) {
    const t = raw.trim();
    if (!t) return 'A target URL is required.';
    const candidate = /^https?:\/\//i.test(t) ? t : `https://${t}`;
    try {
        const url = new URL(candidate);
        if (!url.hostname.includes('.') && url.hostname !== 'localhost') return 'Enter a valid hostname, e.g. example.com.';
        return '';
    } catch {
        return 'Enter a valid URL, e.g. https://example.com.';
    }
}

/* ─── New Scan Modal — one clear form (target → profile → schedule) ───────── */
function NewScanModal({ onClose, onSubmit, error, loading }) {
    const [form, setForm] = useState({
        target: '', selectedProfile: 'full',
        scheduleEnabled: false, scheduleInterval: 'weekly',
    });
    const [touched, setTouched] = useState(false);
    const panelRef = useRef(null);

    // Accessible dialog behavior: focus moves into the dialog on open,
    // Escape closes, and Tab is cycled back into the panel.
    useEffect(() => {
        const previouslyFocused = document.activeElement;
        panelRef.current?.focus?.();
        const handler = (e) => {
            if (e.key === 'Escape') { onClose?.(); return; }
            if (e.key !== 'Tab' || !panelRef.current) return;
            const items = panelRef.current.querySelectorAll(
                'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
            );
            if (!items.length) return;
            const first = items[0], last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
            else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
        };
        window.addEventListener('keydown', handler);
        return () => {
            window.removeEventListener('keydown', handler);
            previouslyFocused?.focus?.();
        };
    }, [onClose]);

    const validationError = validateTarget(form.target);
    const canSubmit = !validationError && !loading;

    const handleSubmit = () => {
        setTouched(true);
        if (validationError) return;
        onSubmit({
            target: form.target.trim(),
            scannerType: 'custom',
            parameters: { profile: form.selectedProfile },
            scheduleEnabled: form.scheduleEnabled,
            scheduleInterval: form.scheduleEnabled ? form.scheduleInterval : null,
        });
    };

    return (
        <div className="modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
            <div ref={panelRef} className="modal-panel max-w-xl" role="dialog" aria-modal="true" aria-label="New security scan" tabIndex={-1}>
                {/* Header */}
                <div className="px-7 py-5 border-b border-slate-200 flex items-start justify-between gap-4">
                    <div>
                        <h2 className="text-[17px] font-bold text-slate-900 tracking-tight">New Security Scan</h2>
                        <p className="text-[12px] text-slate-500 mt-1.5">Choose a target and an analysis depth</p>
                    </div>
                    <button onClick={onClose} className="w-8 h-8 rounded-lg border border-slate-200 bg-slate-50 text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-all flex items-center justify-center flex-shrink-0" aria-label="Close dialog">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                    </button>
                </div>

                {/* Body */}
                <div className="px-7 py-6 max-h-[70vh] overflow-y-auto">
                    {/* Target */}
                    <label className="field-label" htmlFor="scan-target">Target URL or hostname</label>
                    <input
                        id="scan-target"
                        className={`input font-mono !py-3 ${touched && validationError ? '!border-red-500/60' : ''}`}
                        value={form.target}
                        onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                        onBlur={() => setTouched(true)}
                        placeholder="https://example.com"
                        autoFocus
                        aria-required="true"
                        aria-invalid={touched && !!validationError}
                        aria-describedby={touched && validationError ? 'scan-target-error' : undefined}
                    />
                    {touched && validationError ? (
                        <p id="scan-target-error" role="alert" className="text-[12px] text-red-400 mt-2">{validationError}</p>
                    ) : (
                        <p className="text-[12px] text-slate-600 mt-2 font-mono">Only scan systems you own or have written permission to test.</p>
                    )}

                    {/* Engine card */}
                    <div style={{ marginTop: 20, padding: 16, borderRadius: 12, background: 'rgba(6,182,212,0.05)', border: '1px solid rgba(6,182,212,0.2)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                            <div style={{
                                width: 32, height: 32, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                                background: 'rgba(6,182,212,0.12)', border: '1px solid rgba(6,182,212,0.3)', color: '#0891B2',
                            }}>
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                            </div>
                            <div>
                                <p className="text-[13px] font-bold text-slate-800" style={{ margin: 0, fontFamily: CONSOLE.FONT }}>{SCANNER_INFO.name}</p>
                                <p className="text-[13px] text-slate-500 font-mono" style={{ margin: 0 }}>{SCANNER_INFO.fullName}</p>
                            </div>
                        </div>
                        <p className="text-[12px] text-slate-500" style={{ lineHeight: 1.7, margin: '0 0 10px', fontFamily: CONSOLE.FONT }}>{SCANNER_INFO.description}</p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {SCANNER_INFO.detects.map(d => <span key={d} className="chip !text-[9px] !px-2 !py-0.5">{d}</span>)}
                        </div>
                    </div>

                    {/* Profile */}
                    <p className="text-[12.5px] font-bold text-brand-300 uppercase tracking-[0.1em] mt-6 mb-3 font-mono">Scan profile</p>
                    <div role="radiogroup" aria-label="Scan profile" style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 20 }}>
                        {SCAN_PROFILES.map(profile => {
                            const active = form.selectedProfile === profile.id;
                            return (
                                <button key={profile.id} type="button" role="radio" aria-checked={active}
                                    onClick={() => setForm(f => ({ ...f, selectedProfile: profile.id }))}
                                    style={{
                                        padding: 14, borderRadius: 12, textAlign: 'left', cursor: 'pointer', fontFamily: CONSOLE.FONT,
                                        border: `1px solid ${active ? 'rgba(6,182,212,0.5)' : '#E2E8F0'}`,
                                        background: active ? 'rgba(6,182,212,0.09)' : '#FAFBFC',
                                        transition: 'background .15s, border-color .15s',
                                    }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
                                        <ProfileIcon name={profile.icon} color={active ? '#0891B2' : '#64748b'} />
                                        <span style={{ fontSize: 13, fontWeight: 700, color: active ? '#0E7490' : '#64748b' }}>{profile.name}</span>
                                        <span style={{ fontSize: 12, color: '#64748b', marginLeft: 'auto', fontFamily: CONSOLE.MONO }}>{profile.duration}</span>
                                    </div>
                                    <p style={{ fontSize: 12, color: '#475569', margin: 0, fontFamily: CONSOLE.FONT, lineHeight: 1.6 }}>{profile.description}</p>
                                </button>
                            );
                        })}
                    </div>

                    {/* Schedule */}
                    <div style={{ borderRadius: 14, border: '1px solid #E2E8F0', padding: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                            <Toggle checked={form.scheduleEnabled} onChange={v => setForm(f => ({ ...f, scheduleEnabled: v }))} label="Schedule recurring scan" />
                            <div>
                                <p style={{ fontSize: 13, fontWeight: 600, color: '#1e293b', margin: 0, fontFamily: CONSOLE.FONT }}>Recurring scan</p>
                                <p style={{ fontSize: 12, color: '#64748b', margin: 0, fontFamily: CONSOLE.FONT }}>Re-run automatically on a schedule</p>
                            </div>
                        </div>
                        {form.scheduleEnabled && (
                            <div role="radiogroup" aria-label="Schedule interval" style={{ display: 'flex', gap: 8, marginTop: 14, animation: 'fadeIn .3s ease' }}>
                                {['daily', 'weekly', 'monthly'].map(interval => (
                                    <button key={interval} type="button" role="radio" aria-checked={form.scheduleInterval === interval}
                                        onClick={() => setForm(f => ({ ...f, scheduleInterval: interval }))}
                                        style={{
                                            padding: '8px 16px', borderRadius: 10, fontSize: 12.5, fontWeight: 700, cursor: 'pointer', fontFamily: CONSOLE.FONT,
                                            textTransform: 'capitalize',
                                            border: `1px solid ${form.scheduleInterval === interval ? 'rgba(6,182,212,0.5)' : '#E2E8F0'}`,
                                            background: form.scheduleInterval === interval ? 'rgba(6,182,212,0.1)' : '#FAFBFC',
                                            color: form.scheduleInterval === interval ? '#0E7490' : '#64748b',
                                        }}>
                                        {interval}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>

                    {error && <ErrorBanner message={error} style={{ marginBottom: 0, marginTop: 16 }} />}
                </div>

                {/* Footer */}
                <div className="px-7 py-4 border-t border-slate-200 flex items-center justify-end gap-3">
                    <button onClick={onClose} className="btn-ghost">Cancel</button>
                    <ConsoleButton onClick={handleSubmit} busy={loading} disabled={touched && !!validationError} style={{ padding: '10px 20px' }}>
                        {loading ? 'Starting…' : 'Start Scan'}
                    </ConsoleButton>
                </div>
            </div>
        </div>
    );
}

// ─── Main Scans Page ──────────────────────────────────────────────────────────
export default function ScansPage() {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [error, setError] = useState('');
    const [fetchError, setFetchError] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [statusFilter, setStatusFilter] = useState('');
    const [cancellingId, setCancellingId] = useState('');
    const navigate = useNavigate();
    const toast = useToast();

    const fetchScans = async (isRetry = false) => {
        if (isRetry) setFetchError('');
        try {
            const params = {};
            if (statusFilter) params.status = statusFilter;
            const res = await scanAPI.list(params);
            setScans(res.data.data || []);
            setFetchError('');
        } catch (err) {
            setFetchError(err.response?.data?.error?.message || 'Could not load scans. Check your connection and try again.');
        } finally { setLoading(false); }
    };

    useEffect(() => { fetchScans(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [statusFilter]);

    // Poll while any scan is queued/running
    useEffect(() => {
        const hasRunning = scans.some(s => ['queued', 'running'].includes(s.status));
        if (hasRunning) {
            const interval = setInterval(() => fetchScans(), 5000);
            return () => clearInterval(interval);
        }
    }, [scans]); // eslint-disable-line react-hooks/exhaustive-deps

    const handleSubmit = async (data) => {
        setError(''); setSubmitting(true);
        try {
            await scanAPI.create(data);
            setShowModal(false);
            toast('Scan queued — the engine is starting up.', 'success');
            fetchScans();
        } catch (err) {
            const msg = err.response?.data?.error?.message || 'Failed to create scan';
            setError(msg);
            toast(msg, 'error');
        } finally { setSubmitting(false); }
    };

    const handleCancel = async (e, id) => {
        e.stopPropagation();
        setCancellingId(id);
        try {
            await scanAPI.cancel(id);
            toast('Scan cancelled.', 'info');
            fetchScans();
        } catch {
            toast('Could not cancel the scan. It may have already finished.', 'error');
        } finally { setCancellingId(''); }
    };

    const counts = { all: scans.length };
    ['completed', 'running', 'queued', 'failed'].forEach(s => { counts[s] = scans.filter(scan => scan.status === s).length; });

    const tabs = [
        { key: '', label: 'All', count: counts.all },
        { key: 'completed', label: 'Completed', count: counts.completed },
        { key: 'running', label: 'Running', count: counts.running },
        { key: 'queued', label: 'Queued', count: counts.queued },
        { key: 'failed', label: 'Failed', count: counts.failed },
    ];

    const timeAgo = (dateStr) => {
        const diff = Math.floor((Date.now() - new Date(dateStr)) / 86400000);
        return diff === 0 ? 'Today' : diff === 1 ? 'Yesterday' : `${diff} days ago`;
    };

    // Duration from actual start/completion timestamps — '—' when unavailable.
    const scanDuration = (scan) => {
        if (!scan.startedAt || !scan.completedAt) return null;
        const mins = (new Date(scan.completedAt) - new Date(scan.startedAt)) / 60000;
        if (!(mins >= 0)) return null;
        return mins < 1 ? '<1 min' : `${Math.round(mins)} min`;
    };

    return (
        <div style={{ animation: 'fadeIn .35s ease' }}>
            <ConsoleHeader
                kicker="Scan Operations // Queues"
                title="Security Scans"
                sub="Launch, track and manage vulnerability scans"
                accent={CONSOLE.CYAN}
                actions={
                    <ConsoleButton onClick={() => { setError(''); setShowModal(true); }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                        New Scan
                    </ConsoleButton>
                }
            />

            <ConsoleTabs tabs={tabs} active={statusFilter} onChange={setStatusFilter} />

            <GlassCard style={{ padding: 0 }} hover={false}>
                {loading ? (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: '72px 0' }}>
                        <Spinner size={30} />
                        <p style={{ fontSize: 13, color: '#475569', letterSpacing: '0.1em', fontFamily: CONSOLE.MONO }}>LOADING SCANS…</p>
                    </div>
                ) : fetchError ? (
                    <div role="alert">
                        <ConsoleEmpty
                            title="Couldn't load scans"
                            desc={fetchError}
                            icon={<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>}
                            action={<ConsoleButton primary={false} onClick={() => { setLoading(true); fetchScans(true); }}>Try again</ConsoleButton>}
                        />
                    </div>
                ) : scans.length === 0 ? (
                    <ConsoleEmpty
                        title={statusFilter ? `No ${statusFilter} scans` : 'No scans yet'}
                        desc={statusFilter ? 'Try a different status filter, or launch a new scan.' : 'Launch your first security assessment — it takes seconds to start.'}
                        icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>}
                        action={<ConsoleButton onClick={() => setShowModal(true)}>Start Your First Scan</ConsoleButton>}
                    />
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr>
                                    {['Engine', 'Target', 'Findings', 'Status', 'Duration', 'Created', 'Actions'].map(h => (
                                        <th key={h} className="th">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {scans.map((scan) => (
                                    <tr key={scan.id} onClick={() => navigate(`/app/scans/${scan.id}`)} className="table-row">
                                        <td className="td">
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
                                                <div style={{
                                                    width: 34, height: 34, borderRadius: 10, display: 'flex', alignItems: 'center',
                                                    justifyContent: 'center', flexShrink: 0,
                                                    background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.25)', color: '#0891B2',
                                                }} aria-hidden="true">
                                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                                </div>
                                                <div>
                                                    <span style={{ fontSize: 13, fontWeight: 700, color: '#0f172a', fontFamily: CONSOLE.FONT, display: 'block' }}>{SCANNER_INFO.name}</span>
                                                    {scan.parameters?.profile && (
                                                        <span style={{ fontSize: 12.5, color: '#64748b', fontFamily: CONSOLE.MONO, textTransform: 'capitalize' }}>{scan.parameters.profile} profile</span>
                                                    )}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="td">
                                            <p style={{ fontSize: 12.5, fontWeight: 500, color: '#1e293b', fontFamily: CONSOLE.MONO, maxWidth: 200, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', margin: 0 }}>{scan.asset?.target || 'N/A'}</p>
                                            {scan.asset?.name && scan.asset.name !== scan.asset.target && <p style={{ fontSize: 13, color: '#64748b', marginTop: 3, fontFamily: CONSOLE.FONT }}>{scan.asset.name}</p>}
                                        </td>
                                        <td className="td">
                                            <div style={{ display: 'flex', gap: 5, alignItems: 'center', flexWrap: 'wrap' }}>
                                                {SEV_ORDER.filter(k => (scan.severitySummary?.[k] || 0) > 0).map(k => (
                                                    <FindingChip key={k} severity={k} count={scan.severitySummary[k]} />
                                                ))}
                                                {!scan.totalVulnerabilities && <span style={{ color: '#64748b', fontSize: 12, fontFamily: CONSOLE.MONO }}>—</span>}
                                            </div>
                                        </td>
                                        <td className="td">
                                            <StatusPill status={scan.status} progress={scan.progress} />
                                        </td>
                                        <td className="td" style={{ color: '#475569', fontFamily: CONSOLE.MONO, fontSize: 12 }}>
                                            {scanDuration(scan) || '—'}
                                        </td>
                                        <td className="td" style={{ color: '#475569', fontFamily: CONSOLE.MONO, fontSize: 12 }}>{timeAgo(scan.createdAt)}</td>
                                        <td className="td" onClick={e => e.stopPropagation()}>
                                            <div style={{ display: 'flex', gap: 8 }}>
                                                {['running', 'queued'].includes(scan.status) && (
                                                    <button onClick={e => handleCancel(e, scan.id)} disabled={cancellingId === scan.id}
                                                        className="btn-danger !px-3 !py-1.5 !text-[13px]">
                                                        {cancellingId === scan.id ? 'Cancelling…' : 'Cancel'}
                                                    </button>
                                                )}
                                                {scan.status === 'completed' && (
                                                    <button onClick={() => navigate(`/app/scans/${scan.id}`)}
                                                        className="btn-soft !px-3 !py-1.5 !text-[13px] !text-brand-300 !border-brand-500/30">
                                                        View
                                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><polyline points="9 18 15 12 9 6" /></svg>
                                                    </button>
                                                )}
                                                {scan.status === 'failed' && (
                                                    <button onClick={() => navigate(`/app/scans/${scan.id}`)}
                                                        title={scan.errorMessage || 'Scan failed'}
                                                        className="btn-soft !px-3 !py-1.5 !text-[13px] !text-red-300 !border-red-500/30">
                                                        View error
                                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><polyline points="9 18 15 12 9 6" /></svg>
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </GlassCard>

            {showModal && (
                <NewScanModal
                    onClose={() => setShowModal(false)}
                    onSubmit={handleSubmit}
                    error={error}
                    loading={submitting}
                />
            )}

        </div>
    );
}
