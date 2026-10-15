import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { publicScanAPI } from '../services/api';
import { useAuth } from '../store/AuthContext';
import Logo from '../components/Logo';

/* ─────────────────────────────────────────────────────────────────────────────
   Live scan telemetry preview — cycles realistic scanner output in a terminal
   widget so first-time visitors see the product's motion before submitting.
   ───────────────────────────────────────────────────────────────────────────── */
const TELEMETRY_LINES = [
    { text: '$ python main.py --target example.com --scan-kind internal', tone: '#94A3B8' },
    { text: '[discovery] crawling / · 42 pages · 6 forms discovered', tone: '#22D3EE' },
    { text: '[discovery] 14 endpoints · 23 parameters in scope', tone: '#22D3EE' },
    { text: '[headers]   HSTS header missing on /', tone: '#FBBF24' },
    { text: '[cookies]   session cookie missing Secure + HttpOnly', tone: '#FBBF24' },
    { text: '[xss]       reflection confirmed in ?q — context: HTML attribute', tone: '#F87171' },
    { text: '[validation] baseline compared · confidence: high', tone: '#22D3EE' },
    { text: '[ml]        classified: likely genuine — flagged for review', tone: '#67E8F9' },
    { text: '[mitre]     mapped to T1059.007 (Command and Scripting Interpreter)', tone: '#94A3B8' },
    { text: '✔ scan complete — health 82/100 · report generated', tone: '#22D3EE' },
];
const TELEMETRY_TOTAL = TELEMETRY_LINES.length;

function ScanTelemetry() {
    const [count, setCount] = useState(1);

    useEffect(() => {
        let t;
        if (count >= TELEMETRY_TOTAL) {
            t = setTimeout(() => setCount(1), 3400);
        } else {
            t = setTimeout(() => setCount(c => c + 1), 430);
        }
        return () => clearTimeout(t);
    }, [count]);

    const progress = Math.round((Math.min(count, TELEMETRY_TOTAL) / TELEMETRY_TOTAL) * 100);

    return (
        <div className="lp-term">
            <div className="lp-term-bar">
                <span className="lp-term-dot" style={{ background: '#F87171' }} />
                <span className="lp-term-dot" style={{ background: '#FBBF24' }} />
                <span className="lp-term-dot" style={{ background: '#34D399' }} />
                <span className="lp-term-title">vulnscan — live telemetry</span>
            </div>
            <div className="lp-term-body" aria-hidden="true">
                {TELEMETRY_LINES.slice(0, count).map((l, i) => (
                    <p key={i} className="lp-term-line"><span style={{ color: l.tone }}>{l.text}</span></p>
                ))}
                {count < TELEMETRY_TOTAL && <span className="lp-term-cursor" />}
            </div>
            <div className="lp-term-progress">
                <div className="lp-term-progress-fill" style={{ width: `${progress}%` }} />
            </div>
        </div>
    );
}

/* ─── Scroll-reveal wrapper (IntersectionObserver) ───────────────────────── */
function Reveal({ children, delay = 0, className = '' }) {
    const ref = useRef(null);
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;
        if (typeof IntersectionObserver === 'undefined') { setVisible(true); return; }
        const obs = new IntersectionObserver(([entry]) => {
            if (entry.isIntersecting) { setVisible(true); obs.disconnect(); }
        }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
        obs.observe(el);
        return () => obs.disconnect();
    }, []);

    return (
        <div ref={ref} className={`reveal ${visible ? 'is-visible' : ''} ${className}`} style={{ transitionDelay: `${delay}ms` }}>
            {children}
        </div>
    );
}

/* ─── Custom engine stages (real pipeline phases) ─── */
const SCANNERS = [
    { name: 'Discovery', color: '#0891B2' },
    { name: 'Detectors', color: '#F59E0B' },
    { name: 'Validation', color: '#67E8F9' },
    { name: 'Classification', color: '#0891B2' },
    { name: 'MITRE Mapping', color: '#EF4444' },
    { name: 'Reporting', color: '#38BDF8' },
];

/* ─── Feature cards — every claim maps to a real subsystem ─── */
const FEATURES = [
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0891B2" strokeWidth="1.6"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
        title: 'Custom Python scanning engine',
        desc: 'A project-owned engine — same-origin crawler, endpoint and parameter discovery, and ten detector modules covering headers, cookies, CORS, XSS, SQLi, open redirect and path traversal.',
    },
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#67E8F9" strokeWidth="1.6"><path d="M9 11l3 3 8-8"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>,
        title: 'Evidence-based validation',
        desc: 'Every finding carries collected evidence: baseline comparisons, controlled verification, reflection context and a confidence level — no single ambiguous response is treated as proof.',
    },
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0891B2" strokeWidth="1.6"><path d="M12 2a5 5 0 0 1 5 5c0 2.4-1.7 4.4-4 4.9V14h2a1 1 0 0 1 1 1v2h1a1 1 0 0 1 1 1v3H7v-3a1 1 0 0 1 1-1h1v-2a1 1 0 0 1 1-1h2v-2.1c-2.3-.5-4-2.5-4-4.9a5 5 0 0 1 5-5z"/></svg>,
        title: 'ML false-positive filtering',
        desc: 'A locally-trainable Random Forest classifies findings from 34 evidence features — from confirmed to inconclusive. Without a trained model it says so plainly and flags everything for review.',
    },
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="1.6"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
        title: 'MITRE ATT&CK mapping',
        desc: 'Findings are mapped to ATT&CK techniques only where the relationship is justified, with the mapping rationale shown — never implying a vulnerability proves an attacker used a technique.',
    },
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" strokeWidth="1.6"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
        title: 'Audit-ready reports',
        desc: 'Professional PDF and HTML reports generated from persisted scan data: executive summary, evidence, remediation, risk methodology and health-score breakdown — plus CSV and JSON exports.',
    },
    {
        icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10B981" strokeWidth="1.6"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
        title: 'Team workflow & RBAC',
        desc: 'Admin, analyst and viewer roles with per-resource ownership, audit logging, scheduled scans, and token-protected public scan reports that expire after seven days.',
    },
];

/* ─── Stats — real, verifiable figures from the project itself ─── */
const STATS = [
    { number: '10', label: 'custom detector modules in the Python engine', source: '' },
    { number: '34', label: 'evidence features feed the Random Forest classifier', source: '' },
    { number: '5', label: 'verification states from confirmed to inconclusive', source: '' },
    { number: '0–100', label: 'security health score with a documented formula', source: '' },
];

export default function LandingPage() {
    const [target, setTarget] = useState('');
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [submitted, setSubmitted] = useState(null);
    const navigate = useNavigate();
    const { user } = useAuth();
    const inputRef = useRef(null);

    // Pre-fill the email field with the account email once the session loads
    // (only when the field is still empty — never overwrite what user typed).
    useEffect(() => {
        if (user?.email) setEmail(prev => prev || user.email);
    }, [user?.email]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // The email field is always visible; signed-in users get it pre-filled
        // with their account email but can override it.
        let reportEmail = (email || (user?.email ?? '')).trim();
        let rawTarget = target.trim();

        if (!rawTarget) {
            setError('Please enter the URL of the site to scan.');
            inputRef.current?.focus();
            return;
        }
        if (!reportEmail) {
            setError('Please enter your email so we can send the report link.');
            return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reportEmail)) {
            setError('That email address doesn\'t look right — please check it.');
            return;
        }
        // Safety net: if an email accidentally lands in the URL box, swap the two.
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawTarget) && !rawTarget.startsWith('http')) {
            const t = rawTarget;
            rawTarget = reportEmail;
            reportEmail = t.toLowerCase();
            setTarget(rawTarget);
            setEmail(reportEmail);
        }

        setLoading(true);
        try {
            let cleanTarget = rawTarget.replace(/\s+/g, '');
            if (cleanTarget && !cleanTarget.startsWith('http://') && !cleanTarget.startsWith('https://')) {
                cleanTarget = 'https://' + cleanTarget;
            }
            const res = await publicScanAPI.submit({ email: reportEmail.toLowerCase(), targetUrl: cleanTarget });
            const data = res.data.data;
            setSubmitted(data);
            if (user) {
                navigate(`/report/${data.accessToken}`);
            }
        } catch (err) {
            setError(err.response?.data?.error?.message || 'Scan submission failed. Please verify the target and try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ fontFamily: "'Inter', system-ui, sans-serif", background: '#FFFFFF', color: '#0F172A', minHeight: '100vh', overflowX: 'hidden' }}>

            {/* ═══ Sticky Navbar ═══ */}
            <nav className="hs-navbar">
                <div className="hs-navbar-inner">
                    <div className="flex items-center gap-2.5 flex-1">
                        <Logo size={28} withText={false} />
                        <span style={{ fontSize: 16, fontWeight: 700, color: '#0F172A', letterSpacing: '-0.02em' }}>VulnScan<span style={{ color: '#0891B2' }}> Pro</span></span>
                    </div>

                    <div className="hidden lg:flex items-center gap-1">
                        <a href="#features" className="hs-nav-link">Platform</a>
                        <a href="#scanners" className="hs-nav-link">Scan Types</a>
                        <a href="#stats" className="hs-nav-link">Why Us</a>
                    </div>

                    <div className="flex items-center gap-2 flex-1 justify-end">
                        {user ? (
                            <button onClick={() => navigate('/app/dashboard')} className="btn-pill-light" style={{ fontSize: 13 }}>
                                Dashboard →
                            </button>
                        ) : (
                            <>
                                <button onClick={() => navigate('/login')} className="btn-pill-glass" style={{ fontSize: 13 }}>
                                    Log in
                                </button>
                                <button onClick={() => navigate('/register')} className="btn-pill-light" style={{ fontSize: 13 }}>
                                    Sign up
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </nav>

            {/* ═══ Hero Section ═══ */}
            <section className="hs-hero">
                <div style={{ position: 'relative', zIndex: 1, maxWidth: 1200, margin: '0 auto', padding: '0 24px' }}>
                    <Reveal>
                        <p className="hs-hero-badge">Evidence-driven web security assessment</p>
                    </Reveal>
                    <Reveal delay={100}>
                        <h1 className="hs-hero-heading">
                            Find the signal in the{' '}
                            <span className="text-gradient-teal">noise</span>
                        </h1>
                    </Reveal>
                    <Reveal delay={200}>
                        <p className="hs-hero-sub">
                            VulnScan Pro crawls your web application, detects vulnerabilities, and validates every finding with collected evidence —{' '}
                            <br className="hidden md:inline" />
                            so your team fixes real issues instead of chasing false positives.
                        </p>
                    </Reveal>

                    {/* Scan input bar */}
                    <Reveal delay={300}>
                        {submitted && !user ? (
                            <div style={{ maxWidth: 540, margin: '32px auto 0', textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                                <div style={{
                                    background: '#ECFEFF', border: '1px solid rgba(8,145,178,0.3)',
                                    borderRadius: 16, padding: '24px 28px',
                                }}>
                                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#0891B2" strokeWidth="2" style={{ margin: '0 auto 12px' }}>
                                        <polyline points="20 6 9 17 4 12"/>
                                    </svg>
                                    <p style={{ fontSize: 16, fontWeight: 600, color: '#0F172A', marginBottom: 6 }}>Scan submitted!</p>
                                    <p style={{ fontSize: 13, color: 'rgba(15,23,42,0.6)', marginBottom: 16, lineHeight: 1.6 }}>
                                        Your report will be ready shortly. Sign in to view the full results.
                                    </p>
                                    <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                                        <button onClick={() => navigate(`/report/${submitted.accessToken}`)} className="btn-teal" style={{ fontSize: 13, padding: '10px 20px' }}>
                                            View report →
                                        </button>
                                        <button onClick={() => navigate('/register')} className="btn-pill-glass" style={{ fontSize: 13, padding: '10px 20px' }}>
                                            Create account
                                        </button>
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <form onSubmit={handleSubmit}>
                                {/* Two fields side-by-side: website + email, single scan button */}
                                <div style={{ maxWidth: 760, margin: '0 auto' }}>
                                    <div style={{
                                        display: 'flex', alignItems: 'stretch', gap: 10,
                                        flexWrap: 'wrap',
                                    }}>
                                        {/* Website field */}
                                        <div style={{
                                            flex: '1 1 260px', display: 'flex', alignItems: 'center',
                                            background: '#FFFFFF', border: '1px solid #E2E8F0',
                                            borderRadius: 14, padding: '0 6px 0 16px',
                                            boxShadow: '0 2px 10px rgba(15,23,42,0.06)',
                                        }}>
                                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" strokeWidth="2" style={{ flexShrink: 0 }} aria-hidden="true">
                                                <circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                                            </svg>
                                            <input
                                                ref={inputRef}
                                                className="hs-scan-input"
                                                type="text"
                                                value={target}
                                                onChange={e => setTarget(e.target.value)}
                                                placeholder="Website URL — e.g. example.com"
                                                required
                                                style={{ minWidth: 0 }}
                                            />
                                        </div>

                                        {/* Email field */}
                                        <div style={{
                                            flex: '1 1 240px', display: 'flex', alignItems: 'center',
                                            background: '#FFFFFF', border: '1px solid #E2E8F0',
                                            borderRadius: 14, padding: '0 16px',
                                            boxShadow: '0 2px 10px rgba(15,23,42,0.06)',
                                        }}>
                                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" strokeWidth="2" style={{ flexShrink: 0 }} aria-hidden="true">
                                                <rect x="2" y="4" width="20" height="16" rx="3" /><path d="m22 7-10 6L2 7" />
                                            </svg>
                                            <input
                                                className="hs-scan-input"
                                                type="email"
                                                value={email}
                                                onChange={e => setEmail(e.target.value)}
                                                placeholder="Email for the report"
                                                required
                                                autoComplete="email"
                                                style={{ minWidth: 0 }}
                                            />
                                        </div>

                                        {/* Scan button */}
                                        <button className="hs-scan-btn" type="submit" disabled={loading} style={{ borderRadius: 14, margin: 0 }}>
                                            {loading ? (
                                                <svg style={{ animation: 'a2-spin 0.9s linear infinite' }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                                            ) : 'Scan now'}
                                            {!loading && <span>→</span>}
                                        </button>
                                    </div>

                                    {/* Signed-in hint — email was pre-filled from the account */}
                                    {user && (
                                        <p style={{ textAlign: 'center', fontSize: 12, color: '#64748B', marginTop: 10 }}>
                                            Pre-filled with your account email <strong style={{ color: '#0F172A', fontWeight: 600 }}>{user.email}</strong> — edit if you want the report sent elsewhere.
                                        </p>
                                    )}

                                    {error && (
                                        <p role="alert" style={{ textAlign: 'center', color: '#DC2626', fontSize: 13, background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 10, padding: '8px 14px', maxWidth: 540, margin: '12px auto 0' }}>{error}</p>
                                    )}
                                </div>
                            </form>
                        )}
                    </Reveal>

                    {/* Engine pipeline strip */}
                    <Reveal delay={400}>
                        <div className="hs-scanners-strip" id="scanners">
                            <span style={{ fontSize: 13 }}>One engine, end to end:</span>
                            {SCANNERS.map((s, i) => (
                                <span key={i} style={{ fontSize: 13, fontWeight: 700, color: s.color, letterSpacing: '0.04em' }}>
                                    {s.name}
                                </span>
                            ))}
                        </div>
                    </Reveal>
                </div>

                {/* Terminal preview */}
                <Reveal delay={500}>
                    <div style={{ maxWidth: 700, margin: '56px auto 0', padding: '0 24px' }}>
                        <ScanTelemetry />
                    </div>
                </Reveal>
            </section>

            {/* ═══ Stats Section ═══ */}
            <section id="stats" style={{ background: '#F8FAFC', borderTop: '1px solid #E2E8F0', borderBottom: '1px solid #E2E8F0' }}>
                <div style={{ maxWidth: 1200, margin: '0 auto', padding: '72px 24px' }}>
                    <Reveal>
                        <div style={{ textAlign: 'center', marginBottom: 48 }}>
                            <div className="hs-section-badge">
                                <span className="dot" />
                                <span>The Problem</span>
                            </div>
                            <h2 className="hs-section-heading">
                                Reduce complexity that wastes your{' '}
                                <span className="text-gradient-teal">time and money</span>
                            </h2>
                        </div>
                    </Reveal>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 20 }}>
                        {STATS.map((s, i) => (
                            <Reveal key={i} delay={i * 100}>
                                <div className="hs-stat-card">
                                    <div className="hs-stat-number">{s.number}</div>
                                    <div className="hs-stat-label">{s.label}</div>
                                    {s.source && (
                                        <div style={{ fontSize: 13, color: 'rgba(15,23,42,0.4)', marginTop: 8, fontWeight: 600 }}>
                                            {s.source}
                                        </div>
                                    )}
                                </div>
                            </Reveal>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══ Solution / Features Section ═══ */}
            <section id="features" style={{ background: '#FFFFFF' }}>
                <div style={{ maxWidth: 1200, margin: '0 auto', padding: '96px 24px' }}>
                    <Reveal>
                        <div style={{ textAlign: 'center', marginBottom: 56 }}>
                            <div className="hs-section-badge">
                                <span className="dot" style={{ background: '#0891B2' }} />
                                <span>Benefits</span>
                            </div>
                            <h2 className="hs-section-heading">
                                Strengthen your{' '}
                                <span className="text-gradient-teal">cybersecurity</span>{' '}
                                resilience
                            </h2>
                        </div>
                    </Reveal>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 }}>
                        {FEATURES.map((f, i) => (
                            <Reveal key={i} delay={i * 80}>
                                <div className="hs-feature-card" style={{ height: '100%' }}>
                                    <div className="hs-feature-icon">{f.icon}</div>
                                    <h3 style={{ fontSize: 18, fontWeight: 700, color: '#0F172A', marginBottom: 8 }}>{f.title}</h3>
                                    <p style={{ fontSize: 14, color: 'rgba(15,23,42,0.55)', lineHeight: 1.7 }}>{f.desc}</p>
                                </div>
                            </Reveal>
                        ))}
                    </div>
                </div>
            </section>

            {/* ═══ CTA Section ═══ */}
            <section className="hs-cta-band">
                <div style={{ maxWidth: 700, margin: '0 auto', padding: '96px 24px', textAlign: 'center' }}>
                    <Reveal>
                        <div className="hs-section-badge" style={{ justifyContent: 'center' }}>
                            <span className="dot" style={{ background: '#0891B2' }} />
                            <span>Get Started</span>
                        </div>
                        <h2 className="hs-section-heading" style={{ marginBottom: 16 }}>
                            Start scanning in{' '}
                            <span className="text-gradient-teal">under a minute</span>
                        </h2>
                        <p style={{ fontSize: 16, color: 'rgba(15,23,42,0.55)', marginBottom: 36, lineHeight: 1.7 }}>
                            Self-hosted and project-owned. Launch your first assessment in minutes —{' '}
                            and only ever scan targets you own or are authorized to test.
                        </p>
                        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
                            <button onClick={() => navigate('/register')} className="btn-teal" style={{ padding: '14px 32px' }}>
                                Create free account →
                            </button>
                            <button onClick={() => inputRef.current?.focus()} className="btn-pill-glass" style={{ padding: '14px 32px' }}>
                                Try a public scan
                            </button>
                        </div>
                    </Reveal>
                </div>
            </section>

            {/* ═══ Footer ═══ */}
            <footer className="hs-footer">
                <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 24px' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 40, marginBottom: 48 }}>
                        {/* Brand */}
                        <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                                <Logo size={24} withText={false} />
                                <span style={{ fontSize: 15, fontWeight: 700, color: '#0F172A' }}>VulnScan<span style={{ color: '#0891B2' }}> Pro</span></span>
                            </div>
                            <p style={{ fontSize: 13, color: 'rgba(15,23,42,0.45)', lineHeight: 1.7, maxWidth: 260 }}>
                                A final-year engineering project: a custom Python scanning engine with evidence validation, ML-assisted classification and honest, auditable reporting.
                            </p>
                        </div>

                        {/* Platform */}
                        <div>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#0F172A', marginBottom: 16, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Platform</h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                <button onClick={() => navigate('/register')} className="hs-footer-link" style={{ textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>Vulnerability Scanner</button>
                                <button onClick={() => navigate('/register')} className="hs-footer-link" style={{ textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>Asset Management</button>
                                <button onClick={() => navigate('/register')} className="hs-footer-link" style={{ textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>Reporting</button>
                            </div>
                        </div>

                        {/* Engine */}
                        <div>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#0F172A', marginBottom: 16, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Engine</h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                {SCANNERS.map((s, i) => (
                                    <span key={i} className="hs-footer-link">{s.name}</span>
                                ))}
                            </div>
                        </div>

                        {/* Company */}
                        <div>
                            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#0F172A', marginBottom: 16, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Company</h4>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                                <button onClick={() => navigate('/login')} className="hs-footer-link" style={{ textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>Sign In</button>
                                <button onClick={() => navigate('/register')} className="hs-footer-link" style={{ textAlign: 'left', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}>Sign Up</button>
                            </div>
                        </div>
                    </div>

                    {/* Copyright */}
                    <div style={{ borderTop: '1px solid #E2E8F0', paddingTop: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
                        <span style={{ fontSize: 13, color: 'rgba(15,23,42,0.4)' }}>
                            © {new Date().getFullYear()} VulnScan Pro. All rights reserved.
                        </span>
                        <div style={{ display: 'flex', gap: 20 }}>
                            <span className="hs-footer-link" title="Scan only targets you own or have written permission to test">Authorized scanning only</span>
                        </div>
                    </div>
                </div>
            </footer>
        </div>
    );
}
