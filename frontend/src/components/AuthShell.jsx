import Logo from './Logo';
import { useId } from 'react';

/* ─── HostedScan-style split-panel auth layout ──────────────────────────────
   Left panel  = clean white/light (form area)
   Right panel = dark teal/navy (feature showcase)
   ────────────────────────────────────────────────────────────────────────── */

const AUTH_CSS = `
    @keyframes a2-spin { to { transform: rotate(360deg); } }
    @keyframes a2-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* OTP inputs */
    .a2-otp-input {
        width: 46px; height: 54px; text-align: center;
        font-size: 20px; font-weight: 700;
        font-family: 'JetBrains Mono', ui-monospace, monospace;
        background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 12px;
        color: #111827; outline: none; transition: all 0.18s;
    }
    .a2-otp-input:focus {
        border-color: #0891B2;
        box-shadow: 0 0 0 3px rgba(8,145,178,0.12);
    }

    /* Error/warn/success banners */
    .a2-error, .a2-warn, .a2-success {
        display: flex; gap: 8px; align-items: flex-start;
        border-radius: 10px; padding: 10px 12px;
        font-size: 13px; line-height: 1.55; margin-bottom: 16px;
        animation: a2-in 0.25s ease;
    }
    .a2-error { background: #FEF2F2; border: 1px solid #FECACA; color: #B91C1C; }
    .a2-warn { background: #FFFBEB; border: 1px solid #FDE68A; color: #92400E; }
    .a2-success { background: #F0FDF4; border: 1px solid #BBF7D0; color: #166534; }
`;

const SCANNER_LOGOS = [
    { name: 'Discovery', color: '#22D3EE' },
    { name: 'Detectors', color: '#F59E0B' },
    { name: 'Validation', color: '#67E8F9' },
    { name: 'ML Triage', color: '#22D3EE' },
];

const DEFAULT_FEATURES = [
    {
        icon: (
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" strokeWidth="1.8">
                <path d="M9 11l3 3 8-8"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
            </svg>
        ),
        title: 'Evidence-First Scanning',
    },
    {
        icon: (
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" strokeWidth="1.8">
                <path d="M12 2a5 5 0 0 1 5 5c0 2.4-1.7 4.4-4 4.9V14h2a1 1 0 0 1 1 1v2h1a1 1 0 0 1 1 1v3H7v-3a1 1 0 0 1 1-1h1v-2a1 1 0 0 1 1-1h2v-2.1c-2.3-.5-4-2.5-4-4.9a5 5 0 0 1 5-5z"/>
            </svg>
        ),
        title: 'ML-Assisted Triage',
    },
    {
        icon: (
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="1.8">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
            </svg>
        ),
        title: 'Audit-Ready Reports',
    },
];

export default function AuthShell({
    headline = 'WITH VULNSCAN PRO',
    tagline = 'Everything you need to find, classify, and fix web vulnerabilities',
    features = DEFAULT_FEATURES,
    children,
    onBack,
    backLabel = 'Back to home',
}) {
    return (
        <div className="auth-split">
            <style>{AUTH_CSS}</style>

            {/* ── Left Panel: White/Light — Form Area ── */}
            <main className="auth-left">
                {/* Logo — dark text variant for the light panel */}
                <div className="absolute top-8 left-8 lg:left-12 xl:left-16 z-10">
                    <div className="flex items-center gap-2.5">
                        <Logo size={28} withText={false} />
                        <span style={{ fontSize: 17, fontWeight: 700, color: '#0F172A', letterSpacing: '-0.02em' }}>
                            VulnScan<span style={{ color: '#0891B2' }}> Pro</span>
                        </span>
                    </div>
                </div>

                {/* Form content */}
                <div className="w-full max-w-[440px] mx-auto relative z-10">
                    {children}
                </div>

                {/* Back button */}
                {onBack && (
                    <div className="absolute bottom-8 left-8 lg:left-12 xl:left-16">
                        <button
                            type="button"
                            onClick={onBack}
                            className="flex items-center gap-2 text-sm transition-colors"
                            style={{ color: '#6B7280', cursor: 'pointer', background: 'none', border: 'none', fontFamily: 'inherit' }}
                            onMouseEnter={e => e.currentTarget.style.color = '#111827'}
                            onMouseLeave={e => e.currentTarget.style.color = '#6B7280'}
                        >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <polyline points="15 18 9 12 15 6"/>
                            </svg>
                            {backLabel}
                        </button>
                    </div>
                )}
            </main>

            {/* ── Right Panel: Dark Teal — Feature Showcase ── */}
            <aside className="auth-right">
                <div className="relative z-10 w-full max-w-md text-center">
                    {/* Headline */}
                    <p className="text-xs font-medium uppercase tracking-[0.18em] mb-4" style={{ color: 'rgba(245,245,245,0.45)' }}>
                        {headline}
                    </p>
                    <h2 className="text-xl xl:text-2xl font-semibold leading-snug tracking-tight" style={{ color: '#F5F5F5' }}>
                        {tagline}
                    </h2>

                    {/* Feature cards */}
                    <div className="auth-feature-card mt-10">
                        <div className="grid grid-cols-3 gap-6">
                            {features.map((f, i) => (
                                <div key={i} className="flex flex-col items-center text-center gap-3">
                                    <div className="auth-feature-icon">
                                        {f.icon}
                                    </div>
                                    <span className="text-sm font-medium" style={{ color: '#F5F5F5' }}>
                                        {f.title}
                                    </span>
                                </div>
                            ))}
                        </div>

                        {/* Scanner strip */}
                        <div className="mt-8 pt-6" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
                            <p className="text-xs font-medium mb-4" style={{ color: 'rgba(245,245,245,0.55)' }}>
                                Powered by a custom Python scanning engine
                            </p>
                            <div className="flex items-center justify-center gap-6 flex-wrap">
                                {SCANNER_LOGOS.map((s, i) => (
                                    <span
                                        key={i}
                                        className="text-xs font-bold uppercase tracking-wider"
                                        style={{ color: s.color, opacity: 0.85 }}
                                    >
                                        {s.name}
                                    </span>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Trust badge — honest platform principles, not fabricated certifications */}
                    <div className="mt-10 flex items-center justify-center gap-3">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#67E8F9" strokeWidth="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <span className="text-xs" style={{ color: 'rgba(245,245,245,0.45)' }}>
                            Authorized targets only · Evidence-based findings · Self-hosted
                        </span>
                    </div>
                </div>
            </aside>
        </div>
    );
}
