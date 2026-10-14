import { useEffect, useRef, useState, useCallback, createContext, useContext } from 'react';

/* ─────────────────────────────────────────────────────────────────────────────
   VulnScan Pro — Premium shared UI primitives
   Single source of truth for the Tailwind-flavored primitives (auth pages,
   Reports, Assets, Profile, Admin). Console-style primitives live in
   console.jsx; severity/status colors match it exactly.
   ───────────────────────────────────────────────────────────────────────────── */

// ─── Spinner ────────────────────────────────────────────────────────────────
export function Spinner({ size = 16, className = '' }) {
    return (
        <span
            className={`inline-block rounded-full border-2 animate-spin-slow ${className}`}
            style={{
                width: size,
                height: size,
                borderColor: 'rgba(8,145,178,0.25)',
                borderTopColor: '#0891B2',
            }}
            aria-hidden="true"
        />
    );
}

// ─── Skeleton primitives ────────────────────────────────────────────────────
export function SkeletonLine({ width = '100%', height = 13, style = {} }) {
    return <div className="skeleton" style={{ width, height, ...style }} aria-hidden="true" />;
}

/** Placeholder rows for tables while data loads. */
export function SkeletonRows({ rows = 5, cols = 5 }) {
    return (
        <tbody aria-hidden="true">
            {Array.from({ length: rows }).map((_, r) => (
                <tr key={r}>
                    {Array.from({ length: cols }).map((_, c) => (
                        <td key={c} className="td">
                            <SkeletonLine width={c === 0 ? '72%' : `${52 + ((r * 7 + c * 13) % 34)}%`} />
                        </td>
                    ))}
                </tr>
            ))}
        </tbody>
    );
}

/** Full-panel loading placeholder (cards/lists). */
export function SkeletonBlock({ height = 120, style = {} }) {
    return (
        <div style={{ padding: 20, ...style }}>
            <div className="skeleton" style={{ width: '38%', height: 11, marginBottom: 16 }} aria-hidden="true" />
            <div className="skeleton" style={{ height, borderRadius: 12 }} aria-hidden="true" />
        </div>
    );
}

// ─── Toast notifications (aria-live, non-blocking) ──────────────────────────
const ToastContext = createContext(() => {});

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([]);
    const idRef = useRef(0);

    const push = useCallback((message, tone = 'info') => {
        const id = ++idRef.current;
        setToasts(t => [...t.slice(-3), { id, message, tone }]);
        setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4200);
    }, []);

    const TONES = {
        info:    { color: '#0E7490', bg: 'rgba(255,255,255,0.98)',  border: 'rgba(8,145,178,0.4)' },
        success: { color: '#15803d', bg: 'rgba(255,255,255,0.98)',  border: 'rgba(22,163,74,0.4)' },
        error:   { color: '#b91c1c', bg: 'rgba(255,255,255,0.98)', border: 'rgba(220,38,38,0.45)' },
    };

    return (
        <ToastContext.Provider value={push}>
            {children}
            <div
                role="status"
                aria-live="polite"
                style={{ position: 'fixed', bottom: 22, right: 22, zIndex: 90, display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 'min(92vw, 380px)', pointerEvents: 'none' }}
            >
                {toasts.map(t => {
                    const tone = TONES[t.tone] || TONES.info;
                    return (
                        <div
                            key={t.id}
                            className="animate-fade-up"
                            style={{
                                display: 'flex', alignItems: 'flex-start', gap: 10, padding: '12px 16px',
                                borderRadius: 12, background: tone.bg, border: `1px solid ${tone.border}`,
                                boxShadow: '0 10px 30px rgba(15,23,42,0.18)', color: tone.color,
                                fontSize: 13, lineHeight: 1.5, backdropFilter: 'blur(8px)',
                            }}
                        >
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" style={{ flexShrink: 0, marginTop: 1 }}>
                                {t.tone === 'error'
                                    ? <><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></>
                                    : t.tone === 'success'
                                        ? <polyline points="20 6 9 17 4 12" />
                                        : <><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" /></>}
                            </svg>
                            <span>{t.message}</span>
                        </div>
                    );
                })}
            </div>
        </ToastContext.Provider>
    );
}

export function useToast() {
    return useContext(ToastContext);
}

// ─── Page Header ────────────────────────────────────────────────────────────
export function PageHeader({ title, subtitle, actions, kicker }) {
    return (
        <div className="flex items-start justify-between gap-4 mb-8 flex-wrap">
            <div className="min-w-0">
                {kicker && (
                    <p className="text-[12.5px] font-bold text-brand-300 uppercase tracking-[0.16em] font-mono mb-1.5 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-brand-400 inline-block" aria-hidden="true" />
                        {kicker}
                    </p>
                )}
                <h1 className="page-title">{title}</h1>
                {subtitle && <p className="page-sub mt-1.5">{subtitle}</p>}
            </div>
            {actions && <div className="flex items-center gap-3 flex-wrap">{actions}</div>}
        </div>
    );
}

// ─── Inline error banner ────────────────────────────────────────────────────
/** Inline error banner with optional retry/dismiss — used across form-driven pages. */
export function InlineError({ message, onRetry, onDismiss }) {
    if (!message) return null;
    return (
        <div role="alert" className="mb-5 px-4 py-3 rounded-xl text-[13px] font-medium flex items-center gap-2.5 animate-fade-in"
            style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.3)', color: '#b91c1c' }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true" className="flex-shrink-0">
                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span className="flex-1">{message}</span>
            {onRetry && (
                <button onClick={onRetry} className="text-[12px] font-bold px-3 py-1 rounded-lg border border-red-500/40 hover:bg-red-500/10 transition-colors flex-shrink-0">Retry</button>
            )}
            {onDismiss && (
                <button onClick={onDismiss} className="text-slate-400 hover:text-white" aria-label="Dismiss">✕</button>
            )}
        </div>
    );
}

// ─── Stat Card ──────────────────────────────────────────────────────────────
function Sparkline({ data = [], color = '#22D3EE', width = 84, height = 30 }) {
    if (!data || !data.length) return null;
    const max = Math.max(...data, 1);
    const min = Math.min(...data, 0);
    const range = max - min || 1;
    const pts = data.map((v, i) => {
        const x = (i / (data.length - 1)) * width;
        const y = height - ((v - min) / range) * (height - 5) - 2;
        return `${x},${y}`;
    });
    const area = `0,${height} ${pts.join(' ')} ${width},${height}`;
    return (
        <svg width={width} height={height} style={{ overflow: 'visible' }} aria-hidden="true">
            <polygon points={area} fill={color} opacity="0.08" />
            <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="2"
                strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    );
}

export function StatCard({ label, value, sub, accent = '#22D3EE', icon, trend, sparkData, delay = 0 }) {
    return (
        <div
            className="panel panel-hover p-5 animate-fade-up"
            style={{ animationDelay: `${delay}ms` }}
        >
            <div className="flex items-start justify-between mb-4">
                <div
                    className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: `${accent}1f`, border: `1px solid ${accent}30`, color: accent }}
                    aria-hidden="true"
                >
                    {icon}
                </div>
                {sparkData && <Sparkline data={sparkData} color={accent} />}
            </div>
            <p className="text-[13px] font-bold text-slate-500 uppercase tracking-[0.08em] mb-2">{label}</p>
            <p className="text-[30px] font-extrabold leading-none tracking-tight text-slate-900">
                {value ?? '—'}
            </p>
            {sub && (
                <div className="flex items-center gap-2 mt-2.5">
                    {trend !== undefined && (
                        <span
                            className="text-[13px] font-bold px-1.5 py-0.5 rounded-md"
                            style={{
                                color: trend > 0 ? '#F87171' : '#34D399',
                                background: trend > 0 ? 'rgba(248,113,113,0.12)' : 'rgba(52,211,153,0.12)',
                            }}
                        >
                            {trend > 0 ? `↑ +${trend}` : `↓ ${trend}`}
                        </span>
                    )}
                    <p className="text-[12px] text-slate-500">{sub}</p>
                </div>
            )}
        </div>
    );
}

// ─── Badges ─────────────────────────────────────────────────────────────────
const STATUS_MAP = {
    completed: { label: 'Completed', color: '#16A34A', bg: 'rgba(22,163,74,0.08)', border: 'rgba(22,163,74,0.3)', dot: true },
    running:   { label: 'Running',   color: '#0891B2', bg: 'rgba(8,145,178,0.08)', border: 'rgba(8,145,178,0.3)', dot: true, pulse: true },
    queued:    { label: 'Queued',    color: '#0E7490', bg: 'rgba(14,116,144,0.08)', border: 'rgba(14,116,144,0.3)', dot: true },
    failed:    { label: 'Failed',    color: '#DC2626', bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.3)', dot: true },
    cancelled: { label: 'Cancelled', color: '#64748B', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.25)', dot: true },
    generating:{ label: 'Generating',color: '#EA580C', bg: 'rgba(234,88,12,0.08)', border: 'rgba(234,88,12,0.3)', dot: true, pulse: true },
    ready:     { label: 'Ready',     color: '#16A34A', bg: 'rgba(22,163,74,0.08)',  border: 'rgba(22,163,74,0.3)',  dot: true },
    open:      { label: 'Open',      color: '#DC2626', bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.3)' },
    resolved:  { label: 'Resolved',  color: '#16A34A', bg: 'rgba(22,163,74,0.08)',  border: 'rgba(22,163,74,0.3)'  },
    ignored:   { label: 'Ignored',   color: '#0E7490', bg: 'rgba(14,116,144,0.08)', border: 'rgba(14,116,144,0.3)' },
    false_positive: { label: 'False Positive', color: '#64748B', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.25)' },
};

export function StatusBadge({ status, progress }) {
    const cfg = STATUS_MAP[status] || STATUS_MAP.cancelled;
    return (
        <span>
            <span className="badge" style={{ color: cfg.color, background: cfg.bg, borderColor: cfg.border }}>
                {cfg.pulse && <span className="w-1.5 h-1.5 rounded-full animate-pulse-dot" style={{ background: cfg.color }} />}
                {cfg.dot && !cfg.pulse && <span className="w-1.5 h-1.5 rounded-full" style={{ background: cfg.color }} />}
                {cfg.label}
            </span>
            {progress > 0 && ['running', 'queued'].includes(status) && (
                <div className="mt-1.5 w-20 h-1 rounded-full bg-slate-200 overflow-hidden" role="progressbar" aria-valuenow={Math.min(100, progress)} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
                    <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${Math.min(100, progress)}%`, background: `linear-gradient(90deg, #06B6D4, #22D3EE)` }}
                    />
                </div>
            )}
        </span>
    );
}

const SEVERITY_MAP = {
    critical: { label: 'Critical', color: '#B91C1C', bg: 'rgba(220,38,38,0.07)',  border: 'rgba(220,38,38,0.35)' },
    high:     { label: 'High',     color: '#C2410C', bg: 'rgba(234,88,12,0.07)', border: 'rgba(234,88,12,0.35)' },
    medium:   { label: 'Medium',   color: '#A16207', bg: 'rgba(202,138,4,0.08)',  border: 'rgba(202,138,4,0.35)' },
    low:      { label: 'Low',      color: '#1D4ED8', bg: 'rgba(37,99,235,0.07)', border: 'rgba(37,99,235,0.35)' },
    info:     { label: 'Info',     color: '#475569', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.28)' },
};

export function FindingChip({ severity, count }) {
    const cfg = SEVERITY_MAP[severity] || SEVERITY_MAP.info;
    return (
        <span className="badge" style={{ color: cfg.color, background: cfg.bg, borderColor: cfg.border }}>
            {severity.toUpperCase().slice(0, 1)}:{count}
        </span>
    );
}

const GRADE_MAP = {
    'A+': '#16A34A', A: '#16A34A', B: '#0891B2', C: '#CA8A04', D: '#EA580C',
    F: '#DC2626',
};

/** Shows the actual letter grade (A+…F) — never a vague GOOD/POOR label. */
export function GradeBadge({ grade, score }) {
    const g = String(grade || '—').toUpperCase();
    const color = GRADE_MAP[g] || '#94A3B8';
    return (
        <span className="inline-flex items-center gap-2">
            <span
                className="badge font-mono"
                style={{ color, background: `${color}14`, borderColor: `${color}35` }}
                title={score !== undefined ? `Health score ${score}/100` : `Health grade ${g}`}
            >
                {g}
            </span>
            {score !== undefined && (
                <span className="text-[13px] font-semibold text-slate-600 font-mono" style={{ fontVariantNumeric: 'tabular-nums' }}>{score}</span>
            )}
        </span>
    );
}

// ─── Toggle switch ──────────────────────────────────────────────────────────
export function Toggle({ checked, onChange, disabled, label }) {
    return (
        <button
            type="button"
            role="switch"
            aria-checked={checked}
            aria-label={label || (checked ? 'Enabled' : 'Disabled')}
            disabled={disabled}
            onClick={() => onChange(!checked)}
            className="relative w-11 h-6 rounded-full transition-colors duration-200 flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ background: checked ? 'linear-gradient(135deg, #0891B2, #0E7490)' : '#E2E8F0' }}
        >
            <span
                className="absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all duration-200"
                style={{ left: checked ? 22 : 2, boxShadow: '0 1px 3px rgba(15,23,42,0.25)' }}
            />
        </button>
    );
}

// ─── Modal — accessible dialog with focus trap ──────────────────────────────
export function Modal({ onClose, title, subtitle, children, footer, maxWidth = 'max-w-xl' }) {
    const panelRef = useRef(null);

    useEffect(() => {
        const previouslyFocused = document.activeElement;
        // Move focus into the dialog
        const focusables = panelRef.current?.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        (focusables && focusables.length ? focusables[0] : panelRef.current)?.focus?.();

        const handler = (e) => {
            if (e.key === 'Escape') { onClose?.(); return; }
            if (e.key !== 'Tab' || !panelRef.current) return;
            // Simple focus trap: cycle Tab within the dialog
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

    return (
        <div className="modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose?.(); }}>
            <div className={`modal-panel ${maxWidth}`} role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : 'Dialog'} ref={panelRef} tabIndex={-1}>
                {(title || subtitle) && (
                    <div className="px-7 py-5 border-b border-slate-200 flex items-start justify-between gap-4">
                        <div>
                            {title && <h2 className="text-[17px] font-bold text-slate-900 tracking-tight">{title}</h2>}
                            {subtitle && <div className="text-[12px] text-slate-500 mt-1.5">{subtitle}</div>}
                        </div>
                        <button
                            onClick={onClose}
                            className="w-8 h-8 rounded-lg border border-slate-200 bg-slate-50 text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-all flex items-center justify-center flex-shrink-0"
                            aria-label="Close dialog"
                        >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
                                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                            </svg>
                        </button>
                    </div>
                )}
                <div className="px-7 py-6 max-h-[70vh] overflow-y-auto">{children}</div>
                {footer && <div className="px-7 py-4 border-t border-slate-200 flex items-center justify-end gap-3">{footer}</div>}
            </div>
        </div>
    );
}

// ─── Empty state ────────────────────────────────────────────────────────────
export function EmptyState({ icon, title, desc, action, className = '' }) {
    return (
        <div className={`flex flex-col items-center justify-center text-center px-6 py-16 ${className}`}>
            {icon ? (
                <div className="w-16 h-16 rounded-2xl bg-slate-100 border border-slate-200 flex items-center justify-center mb-5 text-slate-400" aria-hidden="true">
                    {icon}
                </div>
            ) : null}
            <p className="text-[15px] font-semibold text-slate-700 mb-2">{title}</p>
            {desc && <p className="text-[13px] text-slate-500 max-w-sm leading-relaxed mb-6">{desc}</p>}
            {action}
        </div>
    );
}

// ─── Error state with retry ─────────────────────────────────────────────────
export function ErrorState({ title = 'Something went wrong', desc, onRetry, className = '' }) {
    return (
        <div className={`flex flex-col items-center justify-center text-center px-6 py-14 ${className}`} role="alert">
            <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-200 flex items-center justify-center mb-5 text-red-500" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
            </div>
            <p className="text-[15px] font-semibold text-slate-700 mb-2">{title}</p>
            {desc && <p className="text-[13px] text-slate-500 max-w-sm leading-relaxed mb-6">{desc}</p>}
            {onRetry && <button onClick={onRetry} className="btn-ghost">Try again</button>}
        </div>
    );
}

// ─── Avatar ─────────────────────────────────────────────────────────────────
export function Avatar({ name, size = 36, className = '' }) {
    const initials = (name || '?')
        .split(' ')
        .filter(Boolean)
        .slice(0, 2)
        .map(p => p[0])
        .join('')
        .toUpperCase() || '?';
    return (
        <div
            className={`rounded-xl bg-brand-gradient flex items-center justify-center font-bold text-white flex-shrink-0 ${className}`}
            style={{ width: size, height: size, fontSize: size * 0.38, boxShadow: '0 1px 4px rgba(8,145,178,0.35)' }}
            aria-hidden="true"
        >
            {initials}
        </div>
    );
}

// ─── Animated counter ───────────────────────────────────────────────────────
export function AnimatedNumber({ value, suffix = '' }) {
    const [display, setDisplay] = useState(0);
    const prevRef = useRef(null);
    useEffect(() => {
        if (!value) { setDisplay(0); return; }
        const target = Number(value) || 0;
        if (prevRef.current === target) return;
        // First value: render immediately — no stale 0 flash
        if (prevRef.current === null) { setDisplay(target); prevRef.current = target; return; }
        prevRef.current = target;
        const from = display;
        const step = Math.max(1, Math.ceil(Math.abs(target - from) / 28));
        let cur = from;
        const timer = setInterval(() => {
            cur += (target > from ? 1 : -1) * step;
            if ((target > from && cur >= target) || (target < from && cur <= target)) { setDisplay(target); clearInterval(timer); }
            else setDisplay(cur);
        }, 24);
        return () => clearInterval(timer);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [value]);
    return <span>{display}{suffix}</span>;
}
