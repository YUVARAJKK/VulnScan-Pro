import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import AuthShell from '../components/AuthShell';

export default function ForgotPasswordPage() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [sent, setSent] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await authAPI.forgotPassword(email);
            setSent(true);
        } catch (err) {
            setError(err.response?.data?.error?.message || 'Something went wrong. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthShell
            headline="ACCOUNT RECOVERY"
            tagline="We'll get you back inside — secure and fast"
            onBack={() => navigate('/')}
        >
            {sent ? (
                <div style={{ textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                    <div style={{
                        width: 56, height: 56, margin: '0 auto 20px', borderRadius: 16,
                        background: '#F0FDF4', border: '1px solid #BBF7D0',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#16A34A" strokeWidth="2.5"><path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/></svg>
                    </div>
                    <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Check your inbox</h1>
                    <p style={{ fontSize: 14, color: '#6B7280', lineHeight: 1.6, marginBottom: 8 }}>
                        If an account exists for <strong style={{ color: '#111827', fontWeight: 600 }}>{email}</strong>,
                        a password reset link is on its way.
                    </p>
                    <p style={{ fontSize: 13, color: '#9CA3AF', marginBottom: 28 }}>The link expires in 1 hour. Check spam if you don't see it.</p>
                    <Link to="/login" style={{ color: '#0891B2', fontSize: 14, fontWeight: 600, textDecoration: 'none' }}>← Back to sign in</Link>
                </div>
            ) : (
                <form onSubmit={handleSubmit} style={{ animation: 'a2-in 0.4s ease' }}>
                    <h1 style={{ fontSize: 28, fontWeight: 700, color: '#111827', marginBottom: 6, letterSpacing: '-0.02em' }}>
                        Reset your password
                    </h1>
                    <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28 }}>
                        Enter your account email and we'll send a secure reset link.
                    </p>

                    {error && (
                        <div className="a2-error">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            {error}
                        </div>
                    )}

                    <div style={{ marginBottom: 24 }}>
                        <label className="auth-label" htmlFor="fp-email">Email address</label>
                        <input
                            id="fp-email"
                            className="auth-input"
                            type="email"
                            value={email}
                            onChange={e => setEmail(e.target.value)}
                            placeholder="you@company.com"
                            required
                            autoFocus
                            autoComplete="email"
                        />
                    </div>

                    <button className={`auth-btn ${email ? 'active' : ''}`} type="submit" disabled={loading}>
                        {loading ? 'Sending…' : 'Send reset link'}
                    </button>

                    <div style={{ textAlign: 'center', marginTop: 24, paddingTop: 18, borderTop: '1px solid #F3F4F6' }}>
                        <span style={{ fontSize: 14, color: '#6B7280' }}>
                            Remembered it?{' '}
                            <Link to="/login" style={{ color: '#0891B2', fontWeight: 600, textDecoration: 'none' }}>Sign in</Link>
                        </span>
                    </div>
                </form>
            )}
        </AuthShell>
    );
}
