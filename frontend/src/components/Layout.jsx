import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import { Avatar } from './ui';
import Logo from './Logo';

const mainNav = [
    {
        path: '/app/dashboard', label: 'Dashboard', minRole: 'viewer',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>,
    },
    {
        path: '/app/assets', label: 'Targets', minRole: 'analyst',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M8 21V7M16 21V12"/></svg>,
    },
    {
        path: '/app/scans', label: 'Scans', minRole: 'viewer',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>,
    },
    {
        path: '/app/reports', label: 'Reports', minRole: 'viewer',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
    },
    {
        path: '/app/admin', label: 'Settings', minRole: 'admin',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
    },
];

const bottomNav = [
    {
        path: '/app/profile', label: 'Profile',
        icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
    },
];

const roleHierarchy = { admin: 3, analyst: 2, viewer: 1 };

const roleLabel = { admin: 'Administrator', analyst: 'Security Analyst', viewer: 'Viewer' };

export default function Layout() {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const userLevel = roleHierarchy[user?.role] || 0;
    const [mobileOpen, setMobileOpen] = useState(false);

    // Close the mobile drawer whenever the route changes
    useEffect(() => { setMobileOpen(false); }, [navigate]);

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    const fullName = `${user?.firstName || ''} ${user?.lastName || ''}`.trim() || user?.email || 'User';

    const visibleMainNav = mainNav.filter((item) => userLevel >= (roleHierarchy[item.minRole] || 0));

    const sidebarInner = (
        <>
            {/* Logo */}
            <div className="px-5 pt-6 pb-5">
                <div className="flex items-center gap-2.5">
                    <Logo size={32} withText={false} />
                    <div>
                        <span style={{ fontSize: 15, fontWeight: 700, color: '#0F172A', letterSpacing: '-0.02em', display: 'block' }}>
                            VulnScan<span style={{ color: '#0891B2' }}> Pro</span>
                        </span>
                        <span style={{ fontSize: 9.5, fontWeight: 700, color: '#64748B', letterSpacing: '0.2em', textTransform: 'uppercase' }}>Security Platform</span>
                    </div>
                </div>
            </div>

            {/* User chip */}
            <div className="mx-4 mb-4 px-3.5 py-3 rounded-2xl border border-slate-200 flex items-center gap-3" style={{ background: '#F8FAFC' }}>
                <Avatar name={fullName} size={34} />
                <div className="min-w-0">
                    <p className="text-[12px] font-semibold text-slate-800 truncate">{fullName}</p>
                    <p className="text-[12px] font-bold uppercase tracking-wider mt-0.5" style={{ color: '#0E7490' }}>
                        {roleLabel[user?.role] || user?.role || 'User'}
                    </p>
                </div>
            </div>

            {/* Nav */}
            <nav className="flex-1 px-4 space-y-1 overflow-y-auto">
                <p className="px-3.5 pt-1 pb-2 text-[12px] font-bold text-slate-400 uppercase tracking-[0.12em]">Menu</p>
                {visibleMainNav.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => (isActive ? 'sidebar-link-active' : 'sidebar-link')}
                    >
                        {item.icon}
                        {item.label}
                    </NavLink>
                ))}
            </nav>

            {/* Bottom */}
            <div className="px-4 py-4 border-t border-slate-200 space-y-1">
                {bottomNav.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => (isActive ? 'sidebar-link-active' : 'sidebar-link')}
                    >
                        {item.icon}
                        {item.label}
                    </NavLink>
                ))}
                <button onClick={handleLogout} className="sidebar-link w-full text-left group">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" className="group-hover:text-red-400 transition-colors">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
                    </svg>
                    Sign Out
                </button>
            </div>
        </>
    );

    return (
        <div className="flex h-screen overflow-hidden bg-surface-950">
            {/* ── Sidebar (desktop) ── */}
            <aside className="w-[248px] hidden md:flex flex-col flex-shrink-0 border-r border-slate-200 bg-white relative z-20">
                {sidebarInner}
            </aside>

            {/* ── Mobile drawer ── */}
            {mobileOpen && (
                <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation menu">
                    <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
                    <aside className="absolute left-0 top-0 bottom-0 w-[264px] flex flex-col bg-white border-r border-slate-200 shadow-2xl" style={{ animation: 'slide-in .22s ease-out both' }}>
                        {sidebarInner}
                    </aside>
                </div>
            )}

            {/* ── Main column ── */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Mobile topbar */}
                <header className="md:hidden sticky top-0 z-30 flex items-center justify-between px-4 py-3 border-b border-slate-200 bg-white">
                    <button
                        onClick={() => setMobileOpen(true)}
                        className="w-10 h-10 -ml-2 rounded-xl flex items-center justify-center text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors"
                        aria-label="Open navigation menu"
                    >
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
                    </button>
                    <Logo size={26} withText={false} />
                    <Avatar name={fullName} size={30} className="!rounded-lg" />
                </header>

                {/* ── Main content ── */}
                <main className="flex-1 overflow-y-auto app-bg relative">
                    <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 relative z-10">
                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    );
}
