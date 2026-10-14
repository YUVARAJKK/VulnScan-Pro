import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import { publicScanAPI } from '../services/api';
import ScanReportView from '../components/ScanReportView';
import Logo from '../components/Logo';

/* ─────────────────────────────────────────────────────────────────────────────
   Public Report Page — shareable scan report
   Renders the SAME unified Assessment Console as the authenticated scan detail
   page (ScanReportView), so results are always identical across the platform.

   Access control: viewing results requires a platform account. New users who
   submit a scan from the homepage are asked to sign up / sign in to unlock the
   report — the token stays in the URL so they land right back here afterwards.
   ───────────────────────────────────────────────────────────────────────────── */

const FONT = "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif";
const MONO = "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace";

/* Robust in-browser file download — appends the anchor to the DOM and delays
   the object-URL revoke, otherwise Chrome can abort the download. */
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

function FullScreenShell({ children }) {
    return (
        <div style={{ minHeight: '100vh', background: '#F6F7F9', fontFamily: FONT, position: 'relative', overflowX: 'hidden' }}>
            <div style={{
                position: 'fixed', inset: 0, pointerEvents: 'none',
                backgroundImage:
                    'linear-gradient(#FAFBFC 1px, transparent 1px), linear-gradient(90deg, #FAFBFC 1px, transparent 1px)',
                backgroundSize: '48px 48px',
                maskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, black 0%, transparent 100%)',
            }} />
            <div style={{ position: 'fixed', top: -180, left: '50%', transform: 'translateX(-50%)', width: 900, height: 500, borderRadius: '50%', pointerEvents: 'none', background: 'radial-gradient(ellipse at center, rgba(6,182,212,0.12) 0%, transparent 72%)' }} />
            <div style={{ position: 'relative', zIndex: 1 }}>{children}</div>
        </div>
    );
}

function LoadingScreen() {
    return (
        <FullScreenShell>
            <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ textAlign: 'center' }}>
                    <div style={{ width: 46, height: 46, border: '3px solid rgba(6,182,212,0.15)', borderTopColor: '#0891B2', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px', boxShadow: 'none' }} />
                    <p style={{ fontSize: 13, color: '#64748b', fontWeight: 500, letterSpacing: '0.04em', fontFamily: MONO }}>LOADING ASSESSMENT…</p>
                    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
            </div>
        </FullScreenShell>
    );
}

function ScanProgressScreen({ scan }) {
    return (
        <FullScreenShell>
            <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
                <div style={{
                    maxWidth: 460, width: '100%', textAlign: 'center', padding: '40px 44px', borderRadius: 16,
                    background: 'rgba(30,41,59,0.66)', border: '1px solid rgba(6,182,212,0.16)',
                    backdropFilter: 'blur(12px)', boxShadow: '0 8px 32px rgba(0,0,0,0.35)',
                }}>
                    <div style={{ width: 58, height: 58, borderRadius: '50%', background: 'rgba(6,182,212,0.08)', border: '1px solid rgba(6,182,212,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
                        <div style={{ width: 26, height: 26, border: '3px solid rgba(6,182,212,0.2)', borderTopColor: '#0891B2', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                    </div>
                    <h2 style={{ fontSize: 18, fontWeight: 700, color: '#0f172a', marginBottom: 8, fontFamily: FONT }}>
                        {scan.status === 'queued' ? 'SCAN QUEUED' : 'SCAN IN PROGRESS'}
                    </h2>
                    <p style={{ fontSize: 13, color: '#475569', marginBottom: 24, lineHeight: 1.6, fontFamily: FONT }}>
                        Assessment of <strong style={{ color: '#1e293b' }}>{scan.hostname || scan.targetUrl}</strong> is {scan.status === 'queued' ? 'waiting for a worker' : 'actively running'}. Auto-refreshing…
                    </p>
                    <div style={{ background: '#EEF2F6', borderRadius: 6, height: 8, overflow: 'hidden', marginBottom: 12 }}>
                        <div style={{ height: '100%', background: 'linear-gradient(90deg,#0891B2,#0891B2,#0E7490)', borderRadius: 6, width: `${Math.max(5, scan.progress || 0)}%`, transition: 'width 1s ease', boxShadow: 'none' }} />
                    </div>
                    <p style={{ fontSize: 12, color: '#64748b', fontFamily: MONO }}>{scan.progress || 0}% · POLLING 3s INTERVAL</p>
                    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
            </div>
        </FullScreenShell>
    );
}

function MessageScreen({ icon, title, desc, action }) {
    return (
        <FullScreenShell>
            <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
                <div style={{
                    maxWidth: 440, width: '100%', textAlign: 'center', padding: 44, borderRadius: 16,
                    background: 'rgba(30,41,59,0.66)', border: '1px solid rgba(6,182,212,0.16)',
                    backdropFilter: 'blur(12px)', boxShadow: '0 8px 32px rgba(0,0,0,0.35)',
                }}>
                    <div style={{ width: 54, height: 54, borderRadius: '50%', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.35)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 18px', color: '#dc2626' }}>{icon}</div>
                    <h2 style={{ fontSize: 18, fontWeight: 700, color: '#0f172a', marginBottom: 8, fontFamily: FONT }}>{title}</h2>
                    <p style={{ fontSize: 13, color: '#475569', marginBottom: 24, lineHeight: 1.6, fontFamily: FONT }}>{desc}</p>
                    {action}
                </div>
            </div>
        </FullScreenShell>
    );
}

/* ─── Auth gate — new users must sign in / sign up to view results ───────── */
function AuthGate({ token }) {
    const navigate = useNavigate();
    const redirect = encodeURIComponent(`/report/${token}`);
    return (
        <FullScreenShell>
            <nav style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: 1100, margin: '0 auto', padding: '18px 28px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9, cursor: 'pointer' }} onClick={() => navigate('/')}>
                    <Logo size={30} />
                </div>
                <button
                    onClick={() => navigate('/login')}
                    style={{ fontSize: 13, fontWeight: 500, color: '#FAFAFA', background: 'rgba(6,182,212,0.9)', border: '1px solid rgba(6,182,212,0.5)', padding: '7px 15px', borderRadius: 8, cursor: 'pointer', fontFamily: FONT, transition: 'background .15s, box-shadow .15s' }}
                    onMouseEnter={e => e.currentTarget.style.boxShadow = '0 0 20px rgba(6,182,212,0.3)'}
                    onMouseLeave={e => e.currentTarget.style.boxShadow = 'none'}
                >
                    Sign in
                </button>
            </nav>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '10vh 24px 24px' }}>
                <div style={{
                    maxWidth: 460, width: '100%', textAlign: 'center', padding: '46px 42px', borderRadius: 18,
                    background: 'rgba(30,41,59,0.66)', border: '1px solid rgba(6,182,212,0.18)',
                    backdropFilter: 'blur(12px)', boxShadow: '0 24px 60px rgba(0,0,0,0.4), inset 0 1px 0 #F1F5F9',
                }}>
                    <div style={{ width: 58, height: 58, borderRadius: 16, background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 18px', color: '#0891B2', boxShadow: 'none' }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                    </div>
                    <h1 style={{ fontSize: 21, fontWeight: 800, color: '#0f172a', margin: '0 0 8px', fontFamily: FONT, letterSpacing: '-0.01em' }}>Sign in to view your report</h1>
                    <p style={{ fontSize: 13.5, color: '#475569', lineHeight: 1.7, margin: '0 0 26px', fontFamily: FONT }}>
                        Your scan results are private and secure. Create a free account — or sign in — to unlock the full
                        vulnerability assessment, MITRE ATT&CK map, compliance posture and report exports.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                        <button
                            onClick={() => navigate(`/register?redirect=${redirect}`)}
                            style={{ width: '100%', padding: '12px', borderRadius: 11, background: 'linear-gradient(135deg,#0891B2,#0891B2)', border: '1px solid rgba(6,182,212,0.45)', color: 'white', fontSize: 14, fontWeight: 700, cursor: 'pointer', fontFamily: FONT, boxShadow: '0 4px 16px rgba(6,182,212,0.35)', transition: 'filter .15s' }}
                            onMouseEnter={e => e.currentTarget.style.filter = 'brightness(1.1)'}
                            onMouseLeave={e => e.currentTarget.style.filter = 'none'}
                        >
                            Create free account
                        </button>
                        <button
                            onClick={() => navigate(`/login?redirect=${redirect}`)}
                            style={{ width: '100%', padding: '12px', borderRadius: 11, background: '#F1F5F9', border: '1px solid #E2E8F0', color: '#1e293b', fontSize: 14, fontWeight: 600, cursor: 'pointer', fontFamily: FONT, transition: 'background .15s, border-color .15s' }}
                            onMouseEnter={e => { e.currentTarget.style.background = '#E8EDF2'; e.currentTarget.style.borderColor = 'rgba(6,182,212,0.4)'; }}
                            onMouseLeave={e => { e.currentTarget.style.background = '#F1F5F9'; e.currentTarget.style.borderColor = '#E2E8F0'; }}
                        >
                            I already have an account — Sign in
                        </button>
                    </div>
                    <p style={{ fontSize: 13, color: '#475569', marginTop: 20, fontFamily: FONT }}>
                        Free forever · No credit card required · Report stays available at this link
                    </p>
                </div>
            </div>
        </FullScreenShell>
    );
}

export default function PublicReportPage() {
    const { token } = useParams();
    const navigate = useNavigate();
    const { user, loading: authLoading } = useAuth();
    const [scan, setScan] = useState(null);
    const [error, setError] = useState('');
    const [downloading, setDownloading] = useState('');
    const [exportError, setExportError] = useState('');

    const fetchScan = useCallback(async () => {
        try {
            const res = await publicScanAPI.getByToken(token);
            setScan(res.data.data);
            setError('');
        } catch (err) {
            const status = err.response?.status;
            if (status === 410) setError({ type: 'expired', message: 'This report link has expired. Request a new scan.' });
            else if (status === 404) setError({ type: 'notfound', message: 'Scan not found or link is invalid.' });
            else setError({ type: 'error', message: err.response?.data?.error?.message || 'Could not load the assessment. Please try again.' });
        }
    }, [token]);

    useEffect(() => {
        fetchScan();
    }, [fetchScan]);

    // Poll while the scan is still queued/running
    useEffect(() => {
        if (!scan || !['queued', 'running'].includes(scan.status)) return;
        const interval = setInterval(async () => {
            try {
                const res = await publicScanAPI.getStatus(token);
                const data = res.data.data;
                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(interval);
                    fetchScan();
                } else {
                    setScan(prev => prev ? { ...prev, ...data } : prev);
                }
            } catch { clearInterval(interval); }
        }, 3000);
        return () => clearInterval(interval);
    }, [scan, token, fetchScan]);

    const handleExport = async (format) => {
        setDownloading(format);
        setExportError('');
        try {
            if (format === 'pdf') {
                const res = await publicScanAPI.exportPdf(token);
                downloadBlob(new Blob([res.data], { type: 'application/pdf' }), `VulnScan-Report-${scan?.hostname || 'target'}.pdf`);
            } else if (format === 'xml') {
                const res = await publicScanAPI.exportXml(token);
                downloadBlob(new Blob([res.data], { type: 'application/xml' }), `VulnScan-Report-${scan?.hostname || 'target'}.xml`);
            } else if (format === 'json') {
                const res = await publicScanAPI.exportJson(token);
                downloadBlob(new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' }), `VulnScan-Intelligence-Report-${scan?.hostname || 'target'}.json`);
            }
        } catch (err) {
            setExportError('Export failed. The report could not be generated — please try again.');
        } finally {
            setDownloading('');
        }
    };

    // ── Auth gate: viewing results requires an account ──
    if (authLoading) return <LoadingScreen />;
    if (!user) return <AuthGate token={token} />;

    // ── Errors ──
    if (error && !scan) {
        const isExpired = error.type === 'expired';
        return (
            <MessageScreen
                icon={
                    isExpired
                        ? <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
                        : <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                }
                title={isExpired ? 'Report link expired' : 'Assessment unavailable'}
                desc={error.message}
                action={
                    <button
                        onClick={() => navigate('/')}
                        style={{ padding: '11px 22px', borderRadius: 10, background: 'linear-gradient(135deg,#0891B2,#0891B2)', border: '1px solid rgba(6,182,212,0.45)', color: 'white', fontSize: 13, fontWeight: 700, cursor: 'pointer', fontFamily: FONT }}
                    >
                        Back to homepage
                    </button>
                }
            />
        );
    }

    if (!scan) return <LoadingScreen />;
    if (['queued', 'running'].includes(scan.status)) return <ScanProgressScreen scan={scan} />;
    if (scan.status === 'failed') {
        return (
            <MessageScreen
                icon={<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>}
                title="Scan failed"
                desc={scan.errorMessage || 'The scan could not complete. Please submit a new scan.'}
                action={
                    <button
                        onClick={() => navigate('/')}
                        style={{ padding: '11px 22px', borderRadius: 10, background: 'linear-gradient(135deg,#0891B2,#0891B2)', border: '1px solid rgba(6,182,212,0.45)', color: 'white', fontSize: 13, fontWeight: 700, cursor: 'pointer', fontFamily: FONT }}
                    >
                        Scan a new target
                    </button>
                }
            />
        );
    }

    // ── Unified report console (same component as the authenticated app) ──
    return (
        <FullScreenShell>
            <div style={{ maxWidth: 1180, margin: '0 auto', padding: '28px 28px 60px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22, gap: 12, flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 9, cursor: 'pointer' }} onClick={() => navigate('/')}>
                        <Logo size={30} />
                        <span style={{ fontSize: 13, color: '#475569', fontFamily: MONO, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Assessment Console</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                            onClick={() => navigate('/')}
                            style={{ fontSize: 12.5, color: '#64748b', background: '#F8FAFC', border: '1px solid #E2E8F0', cursor: 'pointer', padding: '7px 14px', borderRadius: 9, fontFamily: FONT, transition: 'all .15s' }}
                            onMouseEnter={e => { e.currentTarget.style.color = '#1e293b'; e.currentTarget.style.borderColor = 'rgba(6,182,212,0.35)'; }}
                            onMouseLeave={e => { e.currentTarget.style.color = '#64748b'; e.currentTarget.style.borderColor = '#E2E8F0'; }}
                        >
                            New scan
                        </button>
                        <button
                            onClick={() => navigate('/app/dashboard')}
                            style={{ fontSize: 12.5, fontWeight: 600, color: '#FAFAFA', background: 'rgba(6,182,212,0.9)', border: '1px solid rgba(6,182,212,0.5)', cursor: 'pointer', padding: '7px 14px', borderRadius: 9, fontFamily: FONT, transition: 'all .15s' }}
                            onMouseEnter={e => e.currentTarget.style.boxShadow = '0 0 20px rgba(6,182,212,0.3)'}
                            onMouseLeave={e => e.currentTarget.style.boxShadow = 'none'}
                        >
                            Open Console →
                        </button>
                    </div>
                </div>

                {exportError && (
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', marginBottom: 18,
                        background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 10,
                        fontSize: 13, color: '#b91c1c', fontFamily: FONT,
                    }}>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                        <span style={{ flex: 1 }}>{exportError}</span>
                        <button onClick={() => setExportError('')} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 13, fontFamily: FONT }} aria-label="Dismiss">✕</button>
                    </div>
                )}

                <ScanReportView
                    scan={scan}
                    vulns={scan.vulnerabilities || []}
                    mode="public"
                    exportFormats={['pdf', 'xml', 'json']}
                    onExport={handleExport}
                    busy={downloading}
                    backLabel="Home"
                />
            </div>
        </FullScreenShell>
    );
}
