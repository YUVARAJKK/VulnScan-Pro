/** @type {import('tailwindcss').Config} */
export default {
    content: ['./index.html', './src/**/*.{js,jsx}'],
    theme: {
        extend: {
            colors: {
                // Light professional theme — semantic surface scale.
                // The app was originally built with dark-numeric class names
                // (bg-surface-950 for the page background, bg-surface-900 for
                // cards, …). To retheme without touching every component, the
                // SAME token names now map to LIGHT surfaces: higher numbers =
                // "further from the page background" in the original scheme are
                // now the lightest layers (950 = page bg, 900 = card, 875/850 =
                // inputs, 800+ = borders/strong elements).
                surface: {
                    950: '#F6F7F9',
                    925: '#F1F3F6',
                    900: '#FFFFFF',
                    875: '#FFFFFF',
                    850: '#F8FAFC',
                    800: '#E2E8F0',
                    700: '#CBD5E1',
                    600: '#94A3B8',
                    500: '#64748B',
                    400: '#475569',
                },
                // Brand — cyan "scan-signal"; 300/400 remapped to darker
                // ink-compatible tones so text-brand-300/400 stays readable
                // on light surfaces.
                brand: {
                    50: '#ECFEFF',
                    100: '#CFFAFE',
                    200: '#A5F3FC',
                    300: '#0E7490',
                    400: '#0891B2',
                    500: '#06B6D4',
                    600: '#0891B2',
                    700: '#0E7490',
                    800: '#155E75',
                    900: '#164E63',
                    950: '#083344',
                },
                // Accent — cyan (alias of brand)
                accent: {
                    50: '#ECFEFF',
                    100: '#CFFAFE',
                    200: '#A5F3FC',
                    300: '#0E7490',
                    400: '#0891B2',
                    500: '#06B6D4',
                    600: '#0891B2',
                    700: '#0E7490',
                    800: '#155E75',
                    900: '#164E63',
                },
                // Legacy navy alias → slate (kept for legacy refs)
                navy: {
                    400: '#64748B',
                    500: '#475569',
                    600: '#334155',
                    700: '#293548',
                    800: '#1E293B',
                    900: '#0F172A',
                    950: '#0B1120',
                },
                // HostedScan teal palette
                'teal-v3': {
                    50:  '#F0FDFA',
                    100: '#CCFBF1',
                    200: '#99F6E4',
                    300: '#5EEAD4',
                    400: '#2DD4BF',
                    500: '#14B8A6',
                    600: '#0D9488',
                    700: '#0F766E',
                    800: '#115E59',
                    900: '#0A1628',
                    950: '#071115',
                },
                // HostedScan neutral (off-white text)
                'neutral-v3': {
                    50:  '#FAFAFA',
                    100: '#F5F5F5',
                    200: '#E5E5E5',
                    300: '#D4D4D4',
                    400: '#A3A3A3',
                    500: '#737373',
                    600: '#525252',
                    700: '#404040',
                    800: '#262626',
                    900: '#171717',
                },
                // HostedScan slate dark sections
                'slate-v3': {
                    800: '#1A2332',
                    900: '#111827',
                    950: '#0B1120',
                },
                // HostedScan indigo accent
                'indigo-v3': {
                    400: '#818CF8',
                    500: '#6366F1',
                },
                severity: {
                    critical: { DEFAULT: '#DC2626', text: '#B91C1C', border: 'rgba(220,38,38,0.4)' },
                    high:     { DEFAULT: '#EA580C', text: '#C2410C', border: 'rgba(234,88,12,0.4)' },
                    medium:   { DEFAULT: '#CA8A04', text: '#A16207', border: 'rgba(202,138,4,0.4)' },
                    low:      { DEFAULT: '#2563EB', text: '#1D4ED8', border: 'rgba(37,99,235,0.4)' },
                    info:     { DEFAULT: '#64748B', text: '#475569', border: 'rgba(100,116,139,0.4)' },
                },
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
            },
            boxShadow: {
                'panel': '0 1px 2px rgba(15,23,42,0.05), 0 1px 3px rgba(15,23,42,0.06)',
                'panel-hover': '0 4px 6px rgba(15,23,42,0.04), 0 10px 24px rgba(15,23,42,0.08)',
                'glow-brand': '0 1px 3px rgba(6,182,212,0.25)',
                'glow-brand-sm': '0 1px 2px rgba(6,182,212,0.2)',
                'glow-accent': '0 1px 3px rgba(6,182,212,0.25)',
                'glow-teal': '0 1px 3px rgba(6,182,212,0.25)',
                'modal': '0 24px 60px rgba(15,23,42,0.22)',
            },
            backgroundImage: {
                'grid-faint':
                    'linear-gradient(rgba(15,23,42,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(15,23,42,0.03) 1px, transparent 1px)',
                'brand-gradient': 'linear-gradient(135deg, #0891B2 0%, #0E7490 100%)',
                'brand-gradient-soft': 'linear-gradient(135deg, rgba(6,182,212,0.1) 0%, rgba(8,145,178,0.07) 100%)',
                'teal-gradient': 'linear-gradient(135deg, #0891B2 0%, #0E7490 100%)',
                'hero-gradient': 'linear-gradient(180deg, #0E7490 0%, #155E75 50%, #0E7490 100%)',
            },
            animation: {
                'fade-in': 'fade-in 0.3s ease-out both',
                'fade-up': 'fade-up 0.5s ease-out both',
                'slide-in': 'slide-in 0.3s ease-out both',
                'scale-in': 'scale-in 0.2s ease-out both',
                'pulse-dot': 'pulse-dot 2s ease infinite',
                'shimmer': 'shimmer 2s linear infinite',
                'spin-slow': 'spin 1.2s linear infinite',
                'scan-sweep': 'scan-sweep 3s ease-in-out infinite',
                'marquee': 'marquee 30s linear infinite',
                'marquee-reverse': 'marquee 30s linear infinite reverse',
            },
            keyframes: {
                'fade-in': {
                    '0%': { opacity: 0 },
                    '100%': { opacity: 1 },
                },
                'fade-up': {
                    '0%': { opacity: 0, transform: 'translateY(14px)' },
                    '100%': { opacity: 1, transform: 'translateY(0)' },
                },
                'slide-in': {
                    '0%': { opacity: 0, transform: 'translateX(-10px)' },
                    '100%': { opacity: 1, transform: 'translateX(0)' },
                },
                'scale-in': {
                    '0%': { opacity: 0, transform: 'scale(0.96)' },
                    '100%': { opacity: 1, transform: 'scale(1)' },
                },
                'pulse-dot': {
                    '0%, 100%': { opacity: 1, boxShadow: '0 0 4px rgba(8,145,178,0.7)' },
                    '50%': { opacity: 0.45, boxShadow: '0 0 8px rgba(8,145,178,0.25)' },
                },
                'shimmer': {
                    '0%': { backgroundPosition: '-200% 0' },
                    '100%': { backgroundPosition: '200% 0' },
                },
                'scan-sweep': {
                    '0%, 100%': { transform: 'translateX(-120%)', opacity: 0.4 },
                    '50%': { transform: 'translateX(120%)', opacity: 0.9 },
                },
                'marquee': {
                    '0%': { transform: 'translateX(0%)' },
                    '100%': { transform: 'translateX(-50%)' },
                },
            },
        },
    },
    plugins: [],
};
