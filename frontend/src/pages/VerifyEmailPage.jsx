import { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authAPI } from '../services/api';
import AuthShell from '../components/AuthShell';

export default function VerifyEmailPage() {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token') || '';
    const [status, setStatus] = useState('verifying'); // verifying | success | error
    const [message, setMessage] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        let cancelled = false;
        const verify = async () => {
            if (!token) {
                setStatus('error');
                setMessage('Missing verification token. Please use the link from your email.');
                return;
            }
            try {
                const res = await authAPI.verifyEmail(token);
                if (!cancelled) {
                    setStatus('success');
                    setMessage(res.data.message || 'Email verified successfully!');
                }
            } catch (err) {
                if (!cancelled) {
                    setStatus('error');
                    setMessage(err.response?.data?.error?.message || 'Verification failed. The link may be invalid or expired.');
                }
            }
        };
        verify();
        return () => { cancelled = true; };
    }, [token]);

    return (
        <AuthShell
            headline="EMAIL VERIFICATION"
            tagline="Confirm your identity to start scanning"
            onBack={() => navigate('/')}
        >
            <div style={{ textAlign: 'center', animation: 'a2-in 0.4s ease' }}>
                {status === 'verifying' && (
                    <>
                        <div style={{
                            width: 56, height: 56, margin: '0 auto 24px', borderRadius: 16,
                            background: '#ECFEFF', border: '1px solid #A5F3FC',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                            <div
                                style={{
                                    width: 28, height: 28, borderRadius: '50%',
                                    border: '2.5px solid #E5E7EB', borderTopColor: '#0891B2',
                                    animation: 'a2-spin 0.9s linear infinite',
                                }}
                            />
                        </div>
                        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Verifying your email…</h1>
                        <p style={{ fontSize: 14, color: '#6B7280' }}>One moment while we confirm your address.</p>
                    </>
                )}

                {status === 'success' && (
                    <>
                        <div style={{
                            width: 56, height: 56, margin: '0 auto 24px', borderRadius: 16,
                            background: '#F0FDF4', border: '1px solid #BBF7D0',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#16A34A" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        </div>
                        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Email verified</h1>
                        <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>{message}</p>
                        <button className="auth-btn active" type="button" onClick={() => navigate('/login')}>Continue to sign in</button>
                    </>
                )}

                {status === 'error' && (
                    <>
                        <div style={{
                            width: 56, height: 56, margin: '0 auto 24px', borderRadius: 16,
                            background: '#FEF2F2', border: '1px solid #FECACA',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#DC2626" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        </div>
                        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#111827', marginBottom: 8 }}>Verification failed</h1>
                        <p style={{ fontSize: 14, color: '#6B7280', marginBottom: 28, lineHeight: 1.6 }}>{message}</p>
                        <Link to="/login" style={{ color: '#0891B2', fontSize: 14, fontWeight: 600, textDecoration: 'none' }}>Back to sign in</Link>
                    </>
                )}
            </div>
        </AuthShell>
    );
}
