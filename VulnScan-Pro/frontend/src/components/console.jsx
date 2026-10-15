import { useState, useEffect, useRef } from 'react';

/* ─────────────────────────────────────────────────────────────────────────────
   VulnScan Pro — Professional console primitives
   Shared design language for the authenticated command-center pages
   (Dashboard, Scans). Matches the public report page: deep-slate glass
   panels, indigo accents, mono telemetry labels, and the documented
   red/orange/yellow/blue severity palette.
   ───────────────────────────────────────────────────────────────────────────── */

export const CONSOLE = {
    BG: '#F6F7F9',
    PANEL: '#FFFFFF',
    PANEL_BORDER: '#E2E8F0',
    FONT: "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif",
    MONO: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace",
    CYAN: '#0891B2',
    CYAN_TEXT: '#0E7490',
    CYAN_DEEP: '#0E7490',
    CYAN_DEEPER: '#155E75',
    MUTED: '#64748b',
    FAINT: '#94a3b8',
    TEXT: '#334155',
    BRIGHT: '#0f172a',
};

export const SEV_CONFIG = {
    critical: { label: 'Critical', color: '#dc2626', glow: 'rgba(220,38,38,0.35)', bg: 'rgba(220,38,38,0.07)', border: 'rgba(220,38,38,0.35)', text: '#b91c1c' },
    high:     { label: 'High',     color: '#ea580c', glow: 'rgba(234,88,12,0.3)',  bg: 'rgba(234,88,12,0.07)',  border: 'rgba(234,88,12,0.35)', text: '#c2410c' },
    medium:   { label: 'Medium',   color: '#ca8a04', glow: 'rgba(202,138,4,0.3)',  bg: 'rgba(202,138,4,0.08)',  border: 'rgba(202,138,4,0.35)', text: '#a16207' },
    low:      { label: 'Low',      color: '#2563eb', glow: 'rgba(37,99,235,0.3)', bg: 'rgba(37,99,235,0.07)',  border: 'rgba(37,99,235,0.35)', text: '#1d4ed8' },
    info:     { label: 'Info',     color: '#64748b', glow: 'rgba(100,116,139,0.3)', bg: 'rgba(100,116,139,0.08)',  border: 'rgba(100,116,139,0.35)', text: '#475569' },
};

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const STATUS_CONFIG = {
    completed:  { label: 'Completed',  color: '#16a34a', bg: 'rgba(22,163,74,0.08)',   border: 'rgba(22,163,74,0.35)',  pulse: false },
    running:    { label: 'Running',    color: '#0891B2', bg: 'rgba(8,145,178,0.08)', border: 'rgba(8,145,178,0.35)', pulse: true },
    queued:     { label: 'Queued',     color: '#0E7490', bg: 'rgba(14,116,144,0.08)', border: 'rgba(14,116,144,0.35)', pulse: true },
    failed:     { label: 'Failed',     color: '#dc2626', bg: 'rgba(220,38,38,0.08)',   border: 'rgba(220,38,38,0.35)',  pulse: false },
    cancelled:  { label: 'Cancelled',  color: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.35)', pulse: false },
    generating: { label: 'Generating', color: '#ea580c', bg: 'rgba(234,88,12,0.08)',  border: 'rgba(234,88,12,0.35)', pulse: true },
    ready:      { label: 'Ready',      color: '#16a34a', bg: 'rgba(22,163,74,0.08)',   border: 'rgba(22,163,74,0.35)',  pulse: false },
};

/* ─── Loading skeleton line ─────────────────────────────────────────────── */
export function Skeleton({ width = '100%', height = 14, radius = 8, style = {} }) {
    return <div className="skeleton" style={{ width, height, borderRadius: radius, ...style }} aria-hidden="true" />;
}

/* ─── Copy-to-clipboard button with feedback ─────────────────────────────── */
export function CopyButton({ text, label = 'Copy', style = {} }) {
    const [copied, setCopied] = useState(false);
    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1600);
        } catch {
            /* clipboard unavailable — fail silently */
        }
    };
    return (
        <button
            type="button"
            onClick={handleCopy}
            aria-label={copied ? 'Copied to clipboard' : `Copy ${label} to clipboard`}
            style={{
                display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 9px', borderRadius: 7,
                border: `1px solid ${copied ? 'rgba(22,163,74,0.4)' : '#E2E8F0'}`,
                background: copied ? 'rgba(22,163,74,0.08)' : '#F8FAFC',
                color: copied ? '#15803d' : '#64748b', fontSize: 12.5, fontWeight: 700,
                cursor: 'pointer', fontFamily: CONSOLE.MONO, whiteSpace: 'nowrap',
                transition: 'color .15s, border-color .15s, background .15s', ...style,
            }}
        >
            {copied ? (
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12" /></svg>
            ) : (
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
            )}
            {copied ? 'Copied' : label}
        </button>
    );
}

/* ─── Animated count (no flicker on updates) ─────────────────────────────── */
export function AnimatedCount({ value }) {
    const [display, setDisplay] = useState(0);
    const prevRef = useRef(null);
    useEffect(() => {
        const target = Number(value) || 0;
        if (prevRef.current === target) return;
        // First value (or coming from null): render immediately — no 0 flash
        if (prevRef.current === null) { setDisplay(target); prevRef.current = target; return; }
        prevRef.current = target;
        const from = display;
        const step = Math.max(1, Math.ceil(Math.abs(target - from) / 30));
        let cur = from;
        const t = setInterval(() => {
            cur += (target > from ? 1 : -1) * step;
            if ((target > from && cur >= target) || (target < from && cur <= target)) { setDisplay(target); clearInterval(t); }
            else setDisplay(cur);
        }, 24);
        return () => clearInterval(t);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [value]);
    return <span>{display}</span>;
}

/* ─── Glass card ─────────────────────────────────────────────────────────── */
export function GlassCard({ children, style = {}, className = '', hover = true, accent = CONSOLE.CYAN }) {
    const border = CONSOLE.PANEL_BORDER;
    return (
        <div className={className} style={{
            background: CONSOLE.PANEL, border: `1px solid ${border}`, borderRadius: 16,
            boxShadow: '0 1px 2px rgba(15,23,42,0.04), 0 1px 3px rgba(15,23,42,0.06)',
            transition: hover ? 'border-color .2s, transform .2s, box-shadow .2s' : 'none',
            ...style,
        }}
            onMouseEnter={e => { if (hover) { e.currentTarget.style.borderColor = '#CBD5E1'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={e => { if (hover) { e.currentTarget.style.borderColor = border; e.currentTarget.style.transform = 'none'; } }}>
            {children}
        </div>
    );
}

/* ─── Section title with glowing accent dot ──────────────────────────────── */
export function SectionTitle({ title, sub, right, accent = CONSOLE.CYAN, style = {} }) {
    return (
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 16, flexWrap: 'wrap', ...style }}>
            <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: accent, flexShrink: 0 }} />
                    <h3 style={{ fontSize: 14.5, fontWeight: 700, color: CONSOLE.BRIGHT, margin: 0, letterSpacing: '-0.01em', fontFamily: CONSOLE.FONT }}>{title}</h3>
                </div>
                {sub && <p style={{ fontSize: 12, color: CONSOLE.MUTED, margin: '5px 0 0 16px', fontFamily: CONSOLE.FONT }}>{sub}</p>}
            </div>
            {right}
        </div>
    );
}

/* ─── Page header (red-team kicker style) ────────────────────────────────── */
export function ConsoleHeader({ kicker, title, sub, accent = CONSOLE.CYAN, actions }) {
    return (
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
            <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: accent, flexShrink: 0 }} />
                    <span style={{ fontSize: 12.5, fontWeight: 700, color: CONSOLE.CYAN_TEXT, textTransform: 'uppercase', letterSpacing: '0.18em', fontFamily: CONSOLE.MONO }}>
                        {kicker}
                    </span>
                </div>
                <h1 style={{ fontSize: 26, fontWeight: 800, color: CONSOLE.BRIGHT, margin: 0, letterSpacing: '-0.02em', fontFamily: CONSOLE.FONT, lineHeight: 1.15 }}>
                    {title}
                </h1>
                {sub && <p style={{ fontSize: 13, color: CONSOLE.MUTED, margin: '6px 0 0', fontFamily: CONSOLE.FONT }}>{sub}</p>}
            </div>
            {actions && <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>{actions}</div>}
        </div>
    );
}

/* ─── Primary action button (cyan) — supports busy state ─────────────────── */
export function ConsoleButton({ children, onClick, primary = true, disabled, busy = false, type = 'button', style = {} }) {
    return (
        <button
            type={type}
            onClick={onClick}
            disabled={disabled || busy}
            aria-busy={busy || undefined}
            style={{
                display: 'inline-flex', alignItems: 'center', gap: 8, padding: '10px 18px', borderRadius: 11,
                border: primary ? '1px solid rgba(8,145,178,0.45)' : '1px solid #E2E8F0',
                background: primary ? 'linear-gradient(135deg,#0891B2,#06B6D4)' : '#F8FAFC',
                color: primary ? '#fff' : '#475569', fontSize: 13, fontWeight: 700, cursor: disabled || busy ? 'not-allowed' : 'pointer',
                opacity: disabled || busy ? 0.55 : 1, fontFamily: CONSOLE.FONT, whiteSpace: 'nowrap',
                boxShadow: primary ? '0 1px 3px rgba(8,145,178,0.35), inset 0 1px 0 rgba(255,255,255,0.12)' : 'none',
                transition: 'filter .15s, transform .15s, background .15s', ...style,
            }}
            onMouseEnter={e => { if (!disabled && !busy) e.currentTarget.style.filter = 'brightness(1.1)'; }}
            onMouseLeave={e => { if (!disabled && !busy) e.currentTarget.style.filter = 'none'; }}
        >
            {busy && <span style={{ width: 13, height: 13, border: '2px solid rgba(255,255,255,0.35)', borderTopColor: '#fff', borderRadius: '50%', animation: 'consolePulse .8s linear infinite', display: 'inline-block', flexShrink: 0 }} aria-hidden="true" />}
            {children}
        </button>
    );
}

/* ─── KPI card (glass, animated count) — honest: no fake progress bar ─────── */
export function KpiCard({ label, value, accent, icon, sub, delay = 0 }) {
    return (
        <GlassCard style={{ padding: '16px 18px', animationDelay: `${delay}ms` }} accent={accent}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={{ width: 34, height: 34, borderRadius: 10, background: `${accent}14`, border: `1px solid ${accent}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: accent }} aria-hidden="true">
                    {icon}
                </div>
                <span style={{ fontSize: 12, fontWeight: 700, color: CONSOLE.FAINT, letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: CONSOLE.MONO }}>{sub}</span>
            </div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.07em', margin: 0, fontFamily: CONSOLE.FONT }}>{label}</p>
            <p style={{ fontSize: 30, fontWeight: 800, color: CONSOLE.BRIGHT, margin: '4px 0 0', lineHeight: 1.1, fontVariantNumeric: 'tabular-nums', fontFamily: CONSOLE.FONT }}>
                <AnimatedCount value={value} />
            </p>
        </GlassCard>
    );
}

/* ─── Inline error banner with optional retry ────────────────────────────── */
export function ErrorBanner({ message, onRetry, onDismiss, style = {} }) {
    if (!message) return null;
    return (
        <div role="alert" style={{
            display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', marginBottom: 18,
            background: 'rgba(220,38,38,0.06)', border: '1px solid rgba(220,38,38,0.3)', borderRadius: 10,
            fontSize: 13, color: '#b91c1c', fontFamily: CONSOLE.FONT, ...style,
        }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }} aria-hidden="true"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            <span style={{ flex: 1 }}>{message}</span>
            {onRetry && (
                <button onClick={onRetry} style={{
                    background: 'none', border: '1px solid rgba(220,38,38,0.4)', borderRadius: 7, cursor: 'pointer',
                    color: '#b91c1c', fontSize: 12, fontWeight: 700, padding: '4px 12px', fontFamily: CONSOLE.FONT, whiteSpace: 'nowrap',
                }}>Retry</button>
            )}
            {onDismiss && (
                <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 13, fontFamily: CONSOLE.FONT }} aria-label="Dismiss">✕</button>
            )}
        </div>
    );
}

/* ─── Severity pill ──────────────────────────────────────────────────────── */
export function SeverityPill({ severity, count }) {
    const cfg = SEV_CONFIG[severity] || SEV_CONFIG.info;
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 999,
            background: cfg.bg, border: `1px solid ${cfg.border}`, fontSize: 12.5, fontWeight: 700,
            color: cfg.text, textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: CONSOLE.FONT,
            whiteSpace: 'nowrap',
        }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0 }} />
            {cfg.label}
            {count !== undefined && <span style={{ opacity: 0.85, fontVariantNumeric: 'tabular-nums' }}>{count}</span>}
        </span>
    );
}

/* ─── Compact finding chip (C:1 / H:2 …) ────────────────────────────────── */
export function FindingChip({ severity, count }) {
    const cfg = SEV_CONFIG[severity] || SEV_CONFIG.info;
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 7,
            background: cfg.bg, border: `1px solid ${cfg.border}`, fontSize: 12.5, fontWeight: 800,
            color: cfg.text, fontFamily: CONSOLE.MONO, whiteSpace: 'nowrap',
        }}>
            {severity.toUpperCase().slice(0, 1)}:{count}
        </span>
    );
}

/* ─── Status pill with pulse dot ─────────────────────────────────────────── */
export function StatusPill({ status, progress }) {
    const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.cancelled;
    return (
        <span style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'flex-start', gap: 6 }}>
            <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 999,
                background: cfg.bg, border: `1px solid ${cfg.border}`, fontSize: 12.5, fontWeight: 700,
                color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: CONSOLE.FONT,
                whiteSpace: 'nowrap',
            }}>
                <span style={{
                    width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0,
                    boxShadow: 'none',
                    animation: cfg.pulse ? 'consolePulse 1.6s ease-in-out infinite' : 'none',
                }} />
                {cfg.label}
            </span>
            {progress > 0 && ['running', 'queued'].includes(status) && (
                <span style={{ width: 72, height: 4, borderRadius: 3, background: '#EEF2F6', overflow: 'hidden', display: 'block' }}>
                    <span style={{ display: 'block', height: '100%', width: `${Math.min(100, progress)}%`, background: `linear-gradient(90deg,#0891B2,#22D3EE)`, borderRadius: 3, transition: 'width .8s ease' }} />
                </span>
            )}
        </span>
    );
}

/* ─── Console tab bar ────────────────────────────────────────────────────── */
export function ConsoleTabs({ tabs, active, onChange }) {
    return (
        <div role="tablist" style={{
            display: 'flex', gap: 4, overflowX: 'auto', paddingBottom: 0,
            borderBottom: '1px solid rgba(255,255,255,0.08)', marginBottom: 20, scrollbarWidth: 'none',
        }}>
            {tabs.map(t => {
                const isActive = active === t.key;
                return (
                    <button key={t.key} type="button" role="tab" aria-selected={isActive} onClick={() => onChange(t.key)}
                        style={{
                            display: 'inline-flex', alignItems: 'center', gap: 7,                            padding: '10px 15px', borderRadius: '10px 10px 0 0',
                            border: 'none', borderBottom: isActive ? '2px solid #0891B2' : '2px solid transparent',
                            background: isActive ? 'rgba(6,182,212,0.07)' : 'transparent', cursor: 'pointer', whiteSpace: 'nowrap',
                            fontSize: 13, fontWeight: isActive ? 700 : 500,
                            color: isActive ? '#0E7490' : '#64748b', fontFamily: CONSOLE.FONT,
                            transition: 'color .15s, background .15s',
                        }}>
                        {t.label}
                        {t.count !== undefined && (
                            <span style={{
                                padding: '1px 7px', borderRadius: 999, fontSize: 12.5, fontWeight: 700,
                                background: isActive ? 'rgba(6,182,212,0.14)' : 'rgba(15,23,42,0.06)',
                                color: isActive ? '#0E7490' : '#64748b', fontVariantNumeric: 'tabular-nums', fontFamily: CONSOLE.MONO,
                            }}>{t.count}</span>
                        )}
                    </button>
                );
            })}
        </div>
    );
}

/* ─── Empty state ────────────────────────────────────────────────────────── */
export function ConsoleEmpty({ icon, title, desc, action }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', padding: '54px 24px' }}>
            {icon && (
                <div style={{
                    width: 58, height: 58, borderRadius: 16, background: '#F8FAFC',
                    border: '1px solid #E2E8F0', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', color: CONSOLE.MUTED, marginBottom: 18,
                }} aria-hidden="true">{icon}</div>
            )}
            <p style={{ fontSize: 15, fontWeight: 700, color: CONSOLE.TEXT, marginBottom: 6, fontFamily: CONSOLE.FONT }}>{title}</p>
            {desc && <p style={{ fontSize: 13, color: CONSOLE.MUTED, maxWidth: 360, lineHeight: 1.6, marginBottom: 20, fontFamily: CONSOLE.FONT }}>{desc}</p>}
            {action}
        </div>
    );
}
