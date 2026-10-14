import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { scanAPI, reportAPI } from '../services/api';
import ScanReportView from '../components/ScanReportView';
import { CONSOLE, GlassCard, ErrorBanner } from '../components/console';
import { useToast } from '../components/ui';

/* ─────────────────────────────────────────────────────────────────────────────
   Scan Detail Page (authenticated)
   Renders the SAME unified Assessment Console as the public report page
   (ScanReportView). Auth-only extras are enabled through mode="auth":
   vulnerability status workflow and the AI remediation engine.

   Progress stages mirror the REAL engine checkpoints written by
   scanner_engine/main.py: 15% discovery, 40% passive, 65% active,
   80% validation/scoring — no fabricated percentages.
   ───────────────────────────────────────────────────────────────────────────── */

const FONT = CONSOLE.FONT;
const MONO = CONSOLE.MONO;

/* Engine stage → [startPct, endPct, label, description] */
const ENGINE_STAGES = [
    { until: 5,  label: 'Queued',        desc: 'Waiting for a scanner slot' },
    { until: 15, label: 'Initializing',  desc: 'SSRF validation, engine configuration' },
    { until: 40, label: 'Discovery',     desc: 'Crawling pages, parsing robots.txt & sitemap, mapping forms and parameters' },
    { until: 65, label: 'Passive Checks', desc: 'Security headers, cookie flags, CORS, HTTP methods, information disclosure' },
    { until: 80, label: 'Active Testing', desc: 'XSS, SQL injection, open redirect and path traversal probes' },
    { until: 99, label: 'Validating',    desc: 'Evidence deduplication, MITRE mapping, risk & health scoring' },
];

function stageFor(progress) {
    const p = Number(progress) || 0;
    return ENGINE_STAGES.find(s => p < s.until) || ENGINE_STAGES[ENGINE_STAGES.length - 1];
}

function LoadingScreen() {
    return (
        <div style={{ minHeight: '70vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: FONT }}>
            <div style={{ textAlign: 'center' }}>
                <div style={{ width: 46, height: 46, border: '3px solid rgba(6,182,212,0.15)', borderTopColor: '#0891B2', borderRadius: '50%', animation: 'spin .8s linear infinite', margin: '0 auto 18px', boxShadow: 'none' }} />
                <p style={{ fontSize: 12, color: '#64748b', fontWeight: 600, letterSpacing: '0.08em', fontFamily: MONO }}>LOADING ASSESSMENT DATA…</p>
                <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
        </div>
    );
}

function ProgressScreen({ scan, onBack }) {
    const progress = Math.max(0, Math.min(100, Number(scan.progress) || 0));
    const stage = stageFor(progress);
    const isQueued = scan.status === 'queued';

    return (
        <div style={{ minHeight: '70vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: FONT }}>
            <GlassCard style={{ padding: '44px 40px', maxWidth: 560, width: '100%', textAlign: 'center' }}>
                <div style={{ width: 72, height: 72, borderRadius: '50%', background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.28)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 22px', position: 'relative' }}>
                    <div style={{ width: 32, height: 32, border: '3px solid rgba(6,182,212,0.2)', borderTopColor: '#0891B2', borderRadius: '50%', animation: 'spin .8s linear infinite' }} />
                    <span style={{ position: 'absolute', inset: -9, borderRadius: '50%', border: '1px solid rgba(6,182,212,0.12)', animation: 'consolePulse 2s infinite' }} />
                </div>
                <p style={{ fontSize: 13, fontWeight: 700, color: '#0891B2', textTransform: 'uppercase', letterSpacing: '0.18em', fontFamily: MONO, marginBottom: 8 }}>
                    {isQueued ? 'Scan Queued' : 'Assessment In Progress'}
                </p>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a', margin: '0 0 8px', letterSpacing: '-0.01em', wordBreak: 'break-word' }}>
                    {scan.asset?.target || scan.targetUrl || 'Target'}
                </h2>
                <p style={{ fontSize: 13, color: '#64748b', margin: '0 0 24px', fontFamily: MONO }}>
                    {isQueued ? stage.desc : `${stage.label} — ${stage.desc}`}
                </p>

                {/* Real progress bar (engine-reported %, 0 while queued) */}
                <div style={{ background: '#EEF2F6', borderRadius: 6, height: 8, overflow: 'hidden', marginBottom: 8 }} role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
                    <div style={{ height: '100%', width: `${isQueued ? 0 : Math.max(3, progress)}%`, background: 'linear-gradient(90deg,#0891B2,#0891B2,#0E7490)', borderRadius: 6, transition: 'width 1s ease', boxShadow: 'none' }} />
                </div>
                <p style={{ fontSize: 13, color: '#64748b', fontWeight: 600, fontFamily: MONO, marginBottom: 22 }}>
                    {isQueued ? 'QUEUED · 0%' : `${progress}% · AUTO-REFRESHING EVERY 3s`}
                </p>

                {/* Stage checklist — real engine phases */}
                <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
                    {ENGINE_STAGES.slice(1).map((s, i) => {
                        const stageStart = ENGINE_STAGES[i].until; // previous stage's end = this stage's start
                        const done = !isQueued && progress >= s.until;
                        const active = !isQueued && !done && progress >= stageStart;
                        return (
                            <span key={s.label} title={s.desc} style={{
                                fontSize: 12, fontWeight: 700, padding: '3px 10px', borderRadius: 999,
                                background: done ? 'rgba(34,197,94,0.12)' : active ? 'rgba(6,182,212,0.14)' : '#F8FAFC',
                                color: done ? '#16a34a' : active ? '#0E7490' : '#475569',
                                border: `1px solid ${done ? 'rgba(34,197,94,0.3)' : active ? 'rgba(6,182,212,0.3)' : '#E8EDF2'}`,
                                transition: 'all .5s', fontFamily: MONO,
                            }}>
                                {done ? '✓ ' : active ? '● ' : ''}{s.label}
                            </span>
                        );
                    })}
                </div>
                <p style={{ fontSize: 12.5, color: '#475569', margin: '14px 0 0', fontFamily: FONT, lineHeight: 1.6 }}>
                    Active testing sends harmless probes to your target. Progress is reported by the scanning engine itself.
                </p>
                <style>{`
                    @keyframes spin { to { transform: rotate(360deg); } }
                    @keyframes consolePulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
                `}</style>
                {onBack && (
                    <button onClick={onBack} className="btn-ghost" style={{ marginTop: 20 }}>
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="15 18 9 12 15 6" /></svg>
                        Back to Scans
                    </button>
                )}
            </GlassCard>
        </div>
    );
}

/* Terminal-style failure screen — shows the real engine error and offers retry. */
function FailedScreen({ scan, onRetry, retrying, onBack }) {
    return (
        <div style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: FONT }}>
            <GlassCard style={{ padding: '40px 36px', maxWidth: 540, width: '100%', textAlign: 'center' }} hover={false}>
                <div style={{ width: 60, height: 60, borderRadius: '50%', background: 'rgba(239,68,68,0.09)', border: '1px solid rgba(239,68,68,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px', color: '#dc2626' }}>
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                </div>
                <p style={{ fontSize: 13, fontWeight: 700, color: '#dc2626', textTransform: 'uppercase', letterSpacing: '0.18em', fontFamily: MONO, marginBottom: 8 }}>Scan Failed</p>
                <h2 style={{ fontSize: 20, fontWeight: 800, color: '#0f172a', margin: '0 0 8px', wordBreak: 'break-word' }}>
                    {scan.asset?.target || 'Target'}
                </h2>
                <p style={{ fontSize: 13, color: '#475569', margin: '0 0 20px', lineHeight: 1.7 }}>
                    {scan.errorMessage || 'The engine could not complete this assessment.'}
                </p>
                <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
                    <button onClick={onRetry} disabled={retrying} className="btn-brand">
                        {retrying ? 'Retrying…' : 'Retry Scan'}
                    </button>
                    {onBack && <button onClick={onBack} className="btn-ghost">Back to Scans</button>}
                </div>
            </GlassCard>
        </div>
    );
}

function CancelledScreen({ onBack }) {
    return (
        <div style={{ minHeight: '60vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: FONT }}>
            <GlassCard style={{ padding: '40px 36px', maxWidth: 480, width: '100%', textAlign: 'center' }} hover={false}>
                <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(148,163,184,0.08)', border: '1px solid rgba(148,163,184,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 18px', color: '#475569' }}>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><circle cx="12" cy="12" r="10" /><line x1="8" y1="8" x2="16" y2="16" /><line x1="16" y1="8" x2="8" y2="16" /></svg>
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: '#1e293b', margin: '0 0 8px' }}>Scan cancelled</h2>
                <p style={{ fontSize: 13, color: '#64748b', margin: '0 0 20px', lineHeight: 1.7 }}>This assessment was cancelled before completion. Start a new scan whenever you're ready.</p>
                {onBack && <button onClick={onBack} className="btn-ghost">Back to Scans</button>}
            </GlassCard>
        </div>
    );
}

/* Robust in-browser file download — appends the anchor to the DOM and delays
   the object-URL revoke, otherwise Chrome can abort the download (the same
   bug that used to break downloads on the Reports page). */
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function ScanDetailPage() {
    const { id } = useParams();
    const navigate = useNavigate();
    const toast = useToast();
    const [scan, setScan] = useState(null);
    const [vulns, setVulns] = useState([]);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState('');
    const [busy, setBusy] = useState('');
    const [retrying, setRetrying] = useState(false);

    const fetchScanData = useCallback(async () => {
        try {
            const [scanRes, vulnsRes] = await Promise.all([
                scanAPI.get(id),
                scanAPI.getVulnerabilities(id, { limit: 500 }),
            ]);
            setScan(scanRes.data.data);
            setVulns(vulnsRes.data.data || []);
            setFetchError('');
        } catch (err) {
            setFetchError(err.response?.data?.error?.message || 'Could not load this scan. It may not exist or you may not have access.');
        } finally { setLoading(false); }
    }, [id]);

    useEffect(() => { fetchScanData(); }, [fetchScanData]);

    // Poll while the scan is queued/running; stop when terminal
    useEffect(() => {
        if (!scan || !['queued', 'running'].includes(scan.status)) return;
        const interval = setInterval(async () => {
            try {
                const res = await scanAPI.get(id);
                const data = res.data.data;
                if (['completed', 'failed', 'cancelled'].includes(data.status)) {
                    clearInterval(interval);
                    fetchScanData();
                } else {
                    setScan(prev => prev ? { ...prev, ...data } : prev);
                }
            } catch { clearInterval(interval); }
        }, 3000);
        return () => clearInterval(interval);
    }, [scan, fetchScanData, id]);

    const handleRetry = async () => {
        setRetrying(true);
        try {
            await scanAPI.retry(id);
            toast('Scan re-queued.', 'success');
            fetchScanData();
        } catch (err) {
            toast(err.response?.data?.error?.message || 'Could not retry this scan.', 'error');
        } finally { setRetrying(false); }
    };

    const handleExport = async (format) => {
        setBusy(format);
        try {
            if (format === 'csv' || format === 'json') {
                const res = await scanAPI.exportScan(id, format);
                const blob = format === 'csv'
                    ? new Blob([res.data], { type: 'text/csv' })
                    : new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
                downloadBlob(blob, `vuln-report-${String(id).slice(0, 8)}.${format}`);
                toast(`${format.toUpperCase()} export downloaded.`, 'success');
            } else if (format === 'pdf') {
                await reportAPI.create({ scanId: id, title: `Security Assessment — ${scan?.asset?.target || 'Target'}`, format: 'pdf' });
                toast('PDF report queued — track it on the Reports page.', 'success');
                navigate('/app/reports');
            }
        } catch (err) {
            toast(err.response?.data?.error?.message || 'Export failed — please try again.', 'error');
        }
        finally { setBusy(''); }
    };

    if (loading) return <LoadingScreen />;

    if (fetchError && !scan) {
        return (
            <div style={{ maxWidth: 560, margin: '60px auto', fontFamily: FONT }}>
                <GlassCard hover={false} style={{ padding: 0 }}>
                    <ErrorBanner message={fetchError} style={{ margin: 0, border: 'none', borderRadius: '16px 16px 0 0' }} />
                    <div style={{ padding: 20, display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                        <button onClick={fetchScanData} className="btn-ghost">Try again</button>
                        <button onClick={() => navigate('/app/scans')} className="btn-ghost">Back to Scans</button>
                    </div>
                </GlassCard>
            </div>
        );
    }
    if (!scan) return null;

    const backToScans = () => navigate('/app/scans');

    if (scan.status === 'queued' || scan.status === 'running') {
        return <ProgressScreen scan={scan} onBack={backToScans} />;
    }
    if (scan.status === 'failed') {
        return <FailedScreen scan={scan} onRetry={handleRetry} retrying={retrying} onBack={backToScans} />;
    }
    if (scan.status === 'cancelled') {
        return <CancelledScreen onBack={backToScans} />;
    }

    return (
        <>
        <ScanReportView
            scan={scan}
            vulns={vulns}
            mode="auth"
            exportFormats={['pdf', 'csv', 'json']}
            onExport={handleExport}
            busy={busy}
            onBack={backToScans}
            backLabel="Back to Scans"
            kicker="Scan Operations // Report"
        />
        </>
    );
}
