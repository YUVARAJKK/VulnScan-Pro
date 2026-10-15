import { useState } from 'react';
import { useAuth } from '../store/AuthContext';
import { authAPI } from '../services/api';
import { PageHeader, Avatar } from '../components/ui';

function Notice({ type, children }) {
    if (!children) return null;
    const isSuccess = type === 'success';
    return (
        <div className="mb-5 p-3.5 rounded-xl text-[13px] flex items-start gap-2.5 animate-fade-in"
            style={{
                background: isSuccess ? 'rgba(34,197,94,0.08)' : 'rgba(248,113,113,0.08)',
                border: `1px solid ${isSuccess ? 'rgba(34,197,94,0.25)' : 'rgba(248,113,113,0.25)'}`,
                color: isSuccess ? '#6EE7B7' : '#FCA5A5',
            }}>
            <span>{isSuccess ? '✓' : '⚠'}</span>
            <span>{children}</span>
        </div>
    );
}

function SectionCard({ title, subtitle, badge, children }) {
    return (
        <div className="panel p-7 mb-6 animate-fade-up">
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h2 className="text-[16px] font-bold text-slate-100 tracking-tight">{title}</h2>
                    {subtitle && <p className="text-[12px] text-slate-500 mt-1">{subtitle}</p>}
                </div>
                {badge}
            </div>
            {children}
        </div>
    );
}

export default function ProfilePage() {
    const { user, refreshUser } = useAuth();
    const [form, setForm] = useState({ firstName: user?.firstName || '', lastName: user?.lastName || '' });
    const [pwForm, setPwForm] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' });
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    const [mfaSetup, setMfaSetup] = useState(null);
    const [mfaCode, setMfaCode] = useState('');
    const [mfaBusy, setMfaBusy] = useState(false);

    const fullName = `${user?.firstName || ''} ${user?.lastName || ''}`.trim() || user?.email || 'User';

    const handleProfile = async (e) => {
        e.preventDefault(); setMessage(''); setError('');
        try { await authAPI.updateProfile(form); setMessage('Profile updated successfully'); }
        catch (err) { setError(err.response?.data?.error?.message || 'Update failed'); }
    };

    const handlePassword = async (e) => {
        e.preventDefault(); setMessage(''); setError('');
        if (pwForm.newPassword !== pwForm.confirmPassword) { setError('Passwords do not match'); return; }
        try {
            await authAPI.changePassword({ currentPassword: pwForm.currentPassword, newPassword: pwForm.newPassword });
            setPwForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
            setMessage('Password changed successfully');
        } catch (err) { setError(err.response?.data?.error?.message || 'Password change failed'); }
    };

    const handleMfaSetup = async () => {
        setMessage(''); setError(''); setMfaBusy(true);
        try {
            const res = await authAPI.mfaSetup();
            setMfaSetup(res.data.data);
            setMfaCode('');
        } catch (err) { setError(err.response?.data?.error?.message || 'MFA setup failed'); }
        finally { setMfaBusy(false); }
    };

    const handleMfaEnable = async (e) => {
        e.preventDefault(); setMessage(''); setError(''); setMfaBusy(true);
        try {
            await authAPI.mfaEnable(mfaCode);
            setMfaSetup(null);
            setMfaCode('');
            await refreshUser();
            setMessage('Two-factor authentication enabled successfully');
        } catch (err) { setError(err.response?.data?.error?.message || 'Invalid code'); }
        finally { setMfaBusy(false); }
    };

    const handleMfaDisable = async (e) => {
        e.preventDefault(); setMessage(''); setError(''); setMfaBusy(true);
        try {
            await authAPI.mfaDisable(mfaCode);
            setMfaCode('');
            await refreshUser();
            setMessage('Two-factor authentication disabled');
        } catch (err) { setError(err.response?.data?.error?.message || 'Invalid code'); }
        finally { setMfaBusy(false); }
    };

    return (
        <div className="max-w-2xl animate-fade-in">
            <PageHeader
                kicker="Account // Security"
                title="Profile"
                subtitle="Your account, password and two-factor authentication"
            />

            {/* Identity header */}
            <div className="panel p-6 mb-6 flex items-center gap-4 animate-fade-up">
                <Avatar name={fullName} size={56} className="!rounded-2xl" />
                <div>
                    <p className="text-[17px] font-bold text-white">{fullName}</p>
                    <p className="text-[12px] text-slate-500 mt-0.5">{user?.email}</p>
                </div>
                <span className="badge ml-auto" style={{ color: '#0E7490', background: 'rgba(6,182,212,0.1)', borderColor: 'rgba(8,145,178,0.35)' }}>
                    <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse-dot" />
                    {user?.role?.toUpperCase()}
                </span>
            </div>

            <Notice type="success">{message}</Notice>
            <Notice type="error">{error}</Notice>

            <SectionCard title="Personal Information" subtitle="Update your name as it appears across the platform">
                <form onSubmit={handleProfile} className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label className="field-label" htmlFor="profile-first-name">First Name</label>
                            <input id="profile-first-name" className="input" value={form.firstName} onChange={(e) => setForm({ ...form, firstName: e.target.value })} autoComplete="given-name" />
                        </div>
                        <div>
                            <label className="field-label" htmlFor="profile-last-name">Last Name</label>
                            <input id="profile-last-name" className="input" value={form.lastName} onChange={(e) => setForm({ ...form, lastName: e.target.value })} autoComplete="family-name" />
                        </div>
                    </div>
                    <div>
                        <label className="field-label" htmlFor="profile-email">Email</label>
                        <input id="profile-email" className="input opacity-60 cursor-not-allowed" value={user?.email || ''} disabled readOnly aria-describedby="profile-email-hint" />
                        <p id="profile-email-hint" className="text-[13px] text-slate-600 mt-1.5">Email address is your sign-in identity and cannot be changed here.</p>
                    </div>
                    <button type="submit" className="btn-brand">Save Changes</button>
                </form>
            </SectionCard>

            <SectionCard title="Change Password" subtitle="Use at least 8 characters with a mix of cases and symbols">
                <form onSubmit={handlePassword} className="space-y-4">
                    <div>
                        <label className="field-label" htmlFor="profile-current-password">Current Password</label>
                        <input id="profile-current-password" type="password" className="input" value={pwForm.currentPassword} onChange={(e) => setPwForm({ ...pwForm, currentPassword: e.target.value })} required autoComplete="current-password" />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label className="field-label" htmlFor="profile-new-password">New Password</label>
                            <input id="profile-new-password" type="password" className="input" value={pwForm.newPassword} onChange={(e) => setPwForm({ ...pwForm, newPassword: e.target.value })} required minLength={8} autoComplete="new-password" />
                        </div>
                        <div>
                            <label className="field-label" htmlFor="profile-confirm-password">Confirm New Password</label>
                            <input id="profile-confirm-password" type="password" className="input" value={pwForm.confirmPassword} onChange={(e) => setPwForm({ ...pwForm, confirmPassword: e.target.value })} required autoComplete="new-password" />
                        </div>
                    </div>
                    <button type="submit" className="btn-brand">Change Password</button>
                </form>
            </SectionCard>

            <SectionCard
                title="Two-Factor Authentication (MFA)"
                subtitle="Add an extra layer of security with an authenticator app"
                badge={
                    <span className="badge" style={user?.mfaEnabled
                        ? { color: '#34D399', background: 'rgba(34,197,94,0.12)', borderColor: 'rgba(34,197,94,0.3)' }
                        : { color: '#94A3B8', background: 'rgba(148,163,184,0.1)', borderColor: 'rgba(148,163,184,0.25)' }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ background: user?.mfaEnabled ? '#34D399' : '#94A3B8' }} />
                        {user?.mfaEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                }
            >
                {!user?.mfaEnabled && !mfaSetup && (
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                        <p className="text-[13px] text-slate-400 leading-relaxed max-w-md">
                            Protect your account with time-based one-time passwords from Google Authenticator, Authy, 1Password, and more.
                        </p>
                        <button type="button" className="btn-brand" onClick={handleMfaSetup} disabled={mfaBusy}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            {mfaBusy ? 'Generating…' : 'Enable two-factor authentication'}
                        </button>
                    </div>
                )}

                {!user?.mfaEnabled && mfaSetup && (
                    <div className="animate-fade-in">
                        <p className="text-[13px] text-slate-400 mb-4">Scan this secret into your authenticator app, then enter the 6-digit code to confirm:</p>
                        <div className="mb-4">
                            <label className="field-label">Secret key</label>
                            <div className="flex gap-2 items-center">
                                <code className="flex-1 p-3.5 bg-surface-950/80 border border-brand-500/25 rounded-xl text-[13px] font-mono break-all select-all text-brand-200">{mfaSetup.secret}</code>
                                <button type="button" className="btn-soft flex-shrink-0" onClick={() => { navigator.clipboard?.writeText(mfaSetup.secret); setMessage('Secret copied to clipboard'); }}>
                                    Copy
                                </button>
                            </div>
                            <p className="text-[12px] text-slate-500 mt-2">
                                Manual entry: add a new account and paste the secret. Or open the{' '}
                                <a href={mfaSetup.otpauthUrl} className="text-brand-400 hover:text-brand-300 underline underline-offset-2">provisioning link</a>.
                            </p>
                        </div>
                        <form onSubmit={handleMfaEnable} className="flex gap-3 items-end">
                            <div className="flex-1">
                                <label className="field-label">6-digit code</label>
                                <input
                                    type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
                                    value={mfaCode}
                                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                                    className="input font-mono text-lg tracking-[0.5em] text-center !bg-surface-950/80 !border-brand-500/25"
                                    placeholder="••••••" required autoFocus
                                />
                            </div>
                            <button type="submit" className="btn-brand" disabled={mfaBusy || mfaCode.length !== 6}>Confirm & Enable</button>
                        </form>
                        <button type="button" className="mt-3 text-[12px] text-slate-500 hover:text-slate-300 transition-colors" onClick={() => { setMfaSetup(null); setMfaCode(''); }}>Cancel</button>
                    </div>
                )}

                {user?.mfaEnabled && (
                    <div className="animate-fade-in">
                        <p className="text-[13px] text-slate-400 mb-4 leading-relaxed">
                            Two-factor authentication is active. Sign-in will require a code from your authenticator app. To disable, enter your current code:
                        </p>
                        <form onSubmit={handleMfaDisable} className="flex gap-3 items-end">
                            <div className="flex-1">
                                <label className="field-label">Current 6-digit code</label>
                                <input
                                    type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
                                    value={mfaCode}
                                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                                    className="input font-mono text-lg tracking-[0.5em] text-center"
                                    placeholder="••••••" required
                                />
                            </div>
                            <button type="submit" className="btn-danger" disabled={mfaBusy || mfaCode.length !== 6}>Disable MFA</button>
                        </form>
                    </div>
                )}
            </SectionCard>
        </div>
    );
}
