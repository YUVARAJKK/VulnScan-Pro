import { useState, useRef } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import { authAPI } from '../services/api';
import AuthShell from '../components/AuthShell';

// ─── OTP input (6 boxes, auto-advance) ──────────────────────────────────────
function OtpBoxes({ value, onChange }) {
    const refs = useRef([]);
    const setRef = (i) => (el) => { refs.current[i] = el; };

    const handleChange = (i, e) => {
        const v = e.target.value.replace(/\D/g, '');
        if (!v) return;
        const next = (value.slice(0, i) + v[v.length - 1] + value.slice(i + 1)).slice(0, 6);
        onChange(next);
        if (i < 5) refs.current[i + 1]?.focus();
    };

    const handleKeyDown = (i, e) => {
        if (e.key === 'Backspace' && !value[i] && i > 0) refs.current[i - 1]?.focus();
    };

    const handlePaste = (e) => {
        const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
        if (!text) return;
        onChange(text);
        refs.current[Math.min(text.length, 5)]?.focus();
    };

    return (
        <div className="flex gap-2.5 justify-center" onPaste={handlePaste}>
            {[0, 1, 2, 3, 4, 5].map((i) => (
                <input
                    key={i}
                    ref={setRef(i)}
                    className="a2-otp-input"
                    inputMode="numeric"
                    maxLength={1}
                    value={value[i] || ''}
                    onChange={(e) => handleChange(i, e)}
                    onKeyDown={(e) => handleKeyDown(i, e)}
                    autoFocus={i === 0}
                    aria-label={`Digit ${i + 1}`}
                />
            ))}
        </div>
    );
}

/* ─── OAuth placeholder removed — buttons that cannot work are misleading ── */

export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [mfaStep, setMfaStep] = useState(false);
    const [mfaToken, setMfaToken] = useState('');
    const [mfaCode, setMfaCode] = useState('');
    const [unverified, setUnverified] = useState(false);
    const [resent, setResent] = useState(false);
    const [resending, setResending] = useState(false);
    const { login, completeMfaLogin } = useAuth();
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const redirectParam = searchParams.get('redirect') || '';
    // Only allow safe in-app paths — never external or protocol-relative URLs
    const redirect = redirectParam.startsWith('/') && !redirectParam.startsWith('//') ? redirectParam : '';

    const goAfterAuth = () => navigate(redirect || '/app/dashboard');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setUnverified(false);
        setLoading(true);
        try {
            const result = await login(email, password);
            if (result?.mfaRequired) {
                setMfaToken(result.mfaToken);
                setMfaStep(true);
                setLoading(false);
                return;
            }
            setTimeout(goAfterAuth, 300);
        } catch (err) {
            const code = err.response?.data?.error?.code;
            if (code === 'EMAIL_NOT_VERIFIED') {
                setUnverified(true);
                setError(err.response?.data?.error?.message || 'Please verify your email address.');
            } else {
                setError(err.response?.data?.error?.message || 'Invalid credentials. Please check your email and password.');
            }
        } finally {
            setLoading(false);
        }
    };

    const handleMfaSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await completeMfaLogin(mfaToken, mfaCode);
            setTimeout(goAfterAuth, 300);
        } catch (err) {
            setError(err.response?.data?.error?.message || 'Invalid authentication code');
        } finally {
            setLoading(false);
        }
    };

    const handleResend = async () => {
        setResending(true);
        setResent(false);
        try {
            await authAPI.resendVerification(email);
            setResent(true);
        } catch {
            setError('Could not resend verification email. Please try again.');
        } finally {
            setResending(false);
        }
    };

    return (
        <AuthShell onBack={() => navigate('/')}>
            {mfaStep ? (
                <form onSubmit={handleMfaSubmit} style={{ animation: 'a2-in 0.4s ease' }}>
                    <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 6 }}>
                        Two-step verification
                    </h1>
                    <p style={{ fontSize: 14, color: '#6B7280', lineHeight: 1.6, marginBottom: 28 }}>
                        Enter the 6-digit code from your authenticator app for{' '}
                        <strong style={{ color: '#111827', fontWeight: 600 }}>{email}</strong>.
                    </p>

                    {error && (
                        <div className="a2-error">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            {error}
                        </div>
                    )}

                    <OtpBoxes value={mfaCode} onChange={setMfaCode} />

                    <button
                        className={`auth-btn mt-7 ${mfaCode.length === 6 ? 'active' : ''}`}
                        type="submit"
                        disabled={loading || mfaCode.length !== 6}
                    >
                        {loading ? 'Verifying…' : 'Verify & sign in'}
                    </button>

                    <button
                        type="button"
                        style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                            marginTop: 16, background: 'none', border: 'none', cursor: 'pointer',
                            color: '#6B7280', fontSize: 13, fontFamily: 'inherit', width: '100%',
                        }}
                        onClick={() => { setMfaStep(false); setMfaCode(''); setMfaToken(''); }}
                    >
                        ← Back to sign in
                    </button>
                </form>
            ) : (
                <form onSubmit={handleSubmit} style={{ animation: 'a2-in 0.4s ease' }}>
                    <h1 style={{ fontSize: 28, fontWeight: 700, color: '#111827', marginBottom: 6, letterSpacing: '-0.02em' }}>
                        Log in to VulnScan
                    </h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28 }}>
                        Welcome back. Sign in to continue securing your infrastructure.
                    </p>

                    {error && (
                        <div className={unverified ? 'a2-warn' : 'a2-error'}>
                            {unverified ? (
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            ) : (
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            )}
                            <div>
                                <span>{error}</span>
                                {unverified && !resent && (
                                    <button
                                        type="button"
                                        onClick={handleResend}
                                        disabled={resending}
                                        style={{ display: 'block', marginTop: 4, background: 'none', border: 'none', padding: 0, color: '#0891B2', fontSize: 12, fontWeight: 600, cursor: 'pointer', textDecoration: 'underline' }}
                                    >
                                        {resending ? 'Sending…' : 'Resend verification email'}
                                    </button>
                                )}
                                {unverified && resent && (
                                    <span style={{ display: 'block', marginTop: 4, color: '#166534', fontWeight: 600 }}>✓ Verification email sent. Check your inbox.</span>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Email field */}
                    <div style={{ marginBottom: 18 }}>
                        <label className="auth-label" htmlFor="login-email">Email</label>
                        <input
                            id="login-email"
                            className="auth-input"
                            type="email"
                            value={email}
                            onChange={e => setEmail(e.target.value)}
                            placeholder="Email"
                            required
                            autoFocus
                            autoComplete="email"
                        />
                    </div>

                    {/* Password field */}
                    <div style={{ marginBottom: 24 }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                            <label className="auth-label" htmlFor="login-password" style={{ marginBottom: 0 }}>Password</label>
                            <Link
                                to="/forgot-password"
                                style={{ fontSize: 13, color: '#0891B2', fontWeight: 500, textDecoration: 'none' }}
                            >
                                Forgot password?
                            </Link>
                        </div>
                        <div style={{ position: 'relative' }}>
                            <input
                                id="login-password"
                                className="auth-input"
                                type={showPassword ? 'text' : 'password'}
                                value={password}
                                onChange={e => setPassword(e.target.value)}
                                placeholder="Enter your password"
                                required
                                autoComplete="current-password"
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
                    </div>

                    {/* Sign in button */}
                    <button
                        className={`auth-btn ${email && password ? 'active' : ''}`}
                        type="submit"
                        disabled={loading}
                    >
                        {loading ? (
                            <>
                                <svg style={{ animation: 'a2-spin 0.9s linear infinite' }} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                                Signing in…
                            </>
                        ) : 'Sign in'}
                    </button>

                    {/* Footer */}
                    <div style={{ textAlign: 'center', marginTop: 28, paddingTop: 20, borderTop: '1px solid #F3F4F6' }}>
                        <span style={{ fontSize: 14, color: '#6B7280' }}>
                            Don't have an account?{' '}
                            <Link
                                to="/register"
                                style={{ color: '#0891B2', fontWeight: 600, textDecoration: 'underline' }}
                            >
                                Sign Up
                            </Link>
                        </span>
                    </div>
                </form>
            )}
        </AuthShell>
    );
}
