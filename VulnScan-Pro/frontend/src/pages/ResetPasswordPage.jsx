import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authAPI } from '../services/api';
import AuthShell from '../components/AuthShell';

export default function ResetPasswordPage() {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token') || '';
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [done, setDone] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        setLoading(true);
        try {
            await authAPI.resetPassword({ token, newPassword });
            setDone(true);
        } catch (err) {
            setError(err.response?.data?.error?.message || 'Unable to reset password. The link may be invalid or expired.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthShell
            headline="PASSWORD RESET"
            tagline="Choose a new password worth keeping"
            onBack={() => navigate('/')}
        >
            {done ? (
                <div style={{ textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                    <div style={{
                        width: 56, height: 56, margin: '0 auto 20px', borderRadius: 16,
                        background: '#F0FDF4', border: '1px solid #BBF7D0',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#16A34A" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    </div>
                    <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Password updated</h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>Your password has been reset. Sign in with your new credentials.</p>
                    <button className="auth-btn active" type="button" onClick={() => navigate('/login')}>Sign in</button>
                </div>
            ) : !token ? (
                <div style={{ textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                    <div style={{
                        width: 56, height: 56, margin: '0 auto 20px', borderRadius: 16,
                        background: '#FEF2F2', border: '1px solid #FECACA',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#DC2626" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    </div>
                    <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Link missing</h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>This reset link is incomplete. Request a fresh one and try again.</p>
                    <Link to="/forgot-password" style={{ color: '#0891B2', fontSize: 14, fontWeight: 600, textDecoration: 'none' }}>Request a new link →</Link>
                </div>
            ) : (
                <form onSubmit={handleSubmit} style={{ animation: 'a2-in 0.4s ease' }}>
                    <h1 style={{ fontSize: 28, fontWeight: 700, color: '#111827', marginBottom: 6, letterSpacing: '-0.02em' }}>
                        Set a new password
                    </h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28 }}>
                        Make it strong — you'll use it every day.
                    </p>

                    {error && (
                        <div className="a2-error">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            {error}
                        </div>
                    )}

                    <div style={{ marginBottom: 16 }}>
                        <label className="auth-label" htmlFor="rp-password">New password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                id="rp-password"
                                className="auth-input"
                                type={showPassword ? 'text' : 'password'}
                                value={newPassword}
                                onChange={e => setNewPassword(e.target.value)}
                                placeholder="Enter a strong password"
                                required
                                minLength={8}
                                autoFocus
                                style={{ paddingRight: 44 }}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(s => !s)}
                                tabIndex={-1}
                                aria-label="Toggle password visibility"
                                style={{
                                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                                    background: 'none', border: 'none', cursor: 'pointer', color: '#9CA3AF',
                                    padding: 5, display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    borderRadius: 7, transition: 'color 0.15s',
                                }}
                            >
                                {showPassword ? (
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                                ) : (
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                )}
                            </button>
                        </div>
                        <p style={{ fontSize: 12, color: '#9CA3AF', marginTop: 6 }}>8+ characters — the stronger, the better</p>
                    </div>

                    <div style={{ marginBottom: 24 }}>
                        <label className="auth-label" htmlFor="rp-confirm">Confirm new password</label>
                        <input
                            id="rp-confirm"
                            className="auth-input"
                            type="password"
                            value={confirmPassword}
                            onChange={e => setConfirmPassword(e.target.value)}
                            placeholder="Re-enter your new password"
                            required
                            minLength={8}
                        />
                    </div>

                    <button className={`auth-btn ${newPassword && confirmPassword ? 'active' : ''}`} type="submit" disabled={loading}>
                        {loading ? 'Resetting…' : 'Reset password'}
                    </button>

                    <div style={{ textAlign: 'center', marginTop: 24 }}>
                        <Link to="/login" style={{ color: '#6B7280', fontSize: 14, textDecoration: 'none' }}>← Back to sign in</Link>
                    </div>
                </form>
            )}
        </AuthShell>
    );
}
