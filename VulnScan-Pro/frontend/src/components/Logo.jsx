import { useId } from 'react';

/**
 * VulnScan Pro — brand mark.
 * "Radar sweep" tile: a dark telemetry tile with a cyan radar ring, a
 * sweeping sector (the scan signal) and a blip at center — the visual
 * metaphor of the product: a signal sweeping the noise for anomalies.
 */
export default function Logo({ size = 34, withText = true, sub, className = '', textClass = '' }) {
    const raw = useId();
    const clean = raw.replace(/[^a-zA-Z0-9]/g, '');
    const gradId = `vsp-scan-${clean}`;
    const sweepId = `vsp-sector-${clean}`;

    return (
        <div className={`flex items-center gap-2.5 select-none ${className}`}>
            <svg
                width={size}
                height={size}
                viewBox="0 0 48 48"
                fill="none"
                className="flex-shrink-0"
                style={{ filter: 'drop-shadow(0 4px 14px rgba(6,182,212,0.4))' }}
                role={withText ? 'presentation' : 'img'}
                aria-hidden={withText ? true : undefined}
                aria-label={withText ? undefined : 'VulnScan Pro'}
            >
                <defs>
                    <linearGradient id={gradId} x1="8" y1="6" x2="42" y2="44" gradientUnits="userSpaceOnUse">
                        <stop stopColor="#164E63" />
                        <stop offset="1" stopColor="#083344" />
                    </linearGradient>
                    <linearGradient id={sweepId} x1="24" y1="24" x2="40" y2="12" gradientUnits="userSpaceOnUse">
                        <stop stopColor="#22D3EE" stopOpacity="0.85" />
                        <stop offset="1" stopColor="#22D3EE" stopOpacity="0.05" />
                    </linearGradient>
                </defs>

                {/* Tile */}
                <rect x="1.5" y="1.5" width="45" height="45" rx="13" fill={`url(#${gradId})`} />
                <rect x="1.5" y="1.5" width="45" height="45" rx="13" stroke="rgba(34,211,238,0.35)" strokeWidth="1.2" />

                {/* Faint telemetry grid inside the tile */}
                <path d="M17 2v44M31 2v44M2 17h44M2 31h44" stroke="rgba(103,232,249,0.09)" strokeWidth="0.8" />

                {/* Sweeping sector (scan signal) */}
                <path d="M24 24 L40.5 14.5 A19 19 0 0 0 30.5 6.8 Z" fill={`url(#${sweepId})`} />

                {/* Radar rings */}
                <circle cx="24" cy="24" r="17" stroke="rgba(34,211,238,0.35)" strokeWidth="1.3" />
                <circle cx="24" cy="24" r="10.5" stroke="rgba(34,211,238,0.22)" strokeWidth="1" />

                {/* Sweep leading edge */}
                <line x1="24" y1="24" x2="40.5" y2="14.5" stroke="#22D3EE" strokeWidth="1.8" strokeLinecap="round" />

                {/* Center blip */}
                <circle cx="24" cy="24" r="3.1" fill="#22D3EE" />
                <circle cx="24" cy="24" r="6" stroke="rgba(34,211,238,0.5)" strokeWidth="1" />
            </svg>

            {withText && (
                <span className={`leading-none ${textClass}`}>
                    <span className="block text-[16px] font-bold tracking-[-0.01em] text-white">
                        VulnScan<span className="text-brand-400"> Pro</span>
                    </span>
                    {sub && (
                        <span className="block mt-1 text-[9px] font-bold tracking-[0.26em] uppercase text-slate-500">
                            {sub}
                        </span>
                    )}
                </span>
            )}
        </div>
    );
}
