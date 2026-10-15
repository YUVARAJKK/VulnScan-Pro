import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import AuthShell from '../components/AuthShell';

export default function RegisterPage() {
    const [form, setForm] = useState({ firstName: '', lastName: '', email: '', password: '', confirmPassword: '' });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [registered, setRegistered] = useState(false);
    const [autoVerified, setAutoVerified] = useState(false);
    const { register } = useAuth();
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const redirectParam = searchParams.get('redirect') || '';
    // Only allow safe in-app paths — never external or protocol-relative URLs
    const redirect = redirectParam.startsWith('/') && !redirectParam.startsWith('//') ? redirectParam : '';
    const signInHref = redirect ? `/login?redirect=${encodeURIComponent(redirect)}` : '/login';

    const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

    const handleSubmit = async (e) => {
        e.preventDefault(); setError('');
        if (form.password !== form.confirmPassword) { setError('Passwords do not match'); return; }
        setLoading(true);
        try {
            const data = await register({ firstName: form.firstName, lastName: form.lastName, email: form.email, password: form.password });
            setAutoVerified(!!data?.emailVerified);
            setRegistered(true);
        }
        catch (err) { setError(err.response?.data?.error?.message || 'Registration failed'); }
        finally { setLoading(false); }
    };

    return (
        <AuthShell
            headline="GET STARTED"
            tagline="Start scanning in under a minute — no credit card required"
            onBack={() => navigate('/')}
        >
            {registered ? (
                <div style={{ textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                    <div style={{
                        width: 56, height: 56, margin: '0 auto 20px', borderRadius: 16,
                        background: '#F0FDF4', border: '1px solid #BBF7D0',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#16A34A" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    </div>
                    <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Account created</h1>
                    {autoVerified ? (
                        <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>
                            Your account for <strong style={{ color: '#111827', fontWeight: 600 }}>{form.email}</strong> is ready.
                            You can sign in right away.
                        </p>
                    ) : (
                        <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>
                            We sent a verification link to <strong style={{ color: '#111827', fontWeight: 600 }}>{form.email}</strong>.
                            Click it to verify your email, then sign in.
                        </p>
                    )}
                    <button className="auth-btn active" type="button" onClick={() => navigate(signInHref)}>Go to sign in</button>
                </div>
            ) : (
                <form onSubmit={handleSubmit} style={{ animation: 'a2-in 0.4s ease' }}>
                    <h1 style={{ fontSize: 28, fontWeight: 700, color: '#111827', marginBottom: 6, letterSpacing: '-0.02em' }}>
                        Create your account
                    </h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28 }}>
                        No credit card required. Cancel anytime.
                    </p>

                    {error && (
                        <div className="a2-error">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            {error}
                        </div>
                    )}

                    {/* Name fields */}
                    <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                        <div style={{ flex: 1 }}>
                            <label className="auth-label" htmlFor="reg-first">First name</label>
                            <input id="reg-first" name="firstName" className="auth-input" value={form.firstName} onChange={handleChange} required autoFocus autoComplete="given-name" />
                        </div>
                        <div style={{ flex: 1 }}>
                            <label className="auth-label" htmlFor="reg-last">Last name</label>
                            <input id="reg-last" name="lastName" className="auth-input" value={form.lastName} onChange={handleChange} required autoComplete="family-name" />
                        </div>
                    </div>

                    {/* Email */}
                    <div style={{ marginBottom: 16 }}>
                        <label className="auth-label" htmlFor="reg-email">Work email</label>
                        <input id="reg-email" name="email" type="email" className="auth-input" placeholder="you@company.com" value={form.email} onChange={handleChange} required autoComplete="email" />
                    </div>

                    {/* Password */}
                    <div style={{ marginBottom: 16 }}>
                        <label className="auth-label" htmlFor="reg-password">Password</label>
                        <input id="reg-password" name="password" type="password" className="auth-input" value={form.password} onChange={handleChange} required minLength={8} autoComplete="new-password" />
                        <p style={{ fontSize: 12, color: '#9CA3AF', marginTop: 6 }}>8+ characters — the stronger, the better</p>
                    </div>

                    {/* Confirm password */}
                    <div style={{ marginBottom: 24 }}>
                        <label className="auth-label" htmlFor="reg-confirm">Confirm password</label>
                        <input id="reg-confirm" name="confirmPassword" type="password" className="auth-input" value={form.confirmPassword} onChange={handleChange} required autoComplete="new-password" />
                    </div>

                    <button
                        className={`auth-btn ${form.email && form.password && form.firstName ? 'active' : ''}`}
                        type="submit"
                        disabled={loading}
                    >
                        {loading ? (
                            <>
                                <svg style={{ animation: 'a2-spin 0.9s linear infinite' }} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                                Creating account…
                            </>
                        ) : 'Create account'}
                    </button>

                    <div style={{ textAlign: 'center', marginTop: 24, paddingTop: 18, borderTop: '1px solid #F3F4F6' }}>
                        <span style={{ fontSize: 14, color: '#6B7280' }}>
                            Already have an account?{' '}
                            <Link to="/login" style={{ color: '#0891B2', fontWeight: 600, textDecoration: 'underline' }}>Sign in</Link>
                        </span>
                    </div>
                </form>
            )}
        </AuthShell>
    );
}
