import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
    const [user, setUser] = useState(() => {
        const saved = localStorage.getItem('user');
        return saved ? JSON.parse(saved) : null;
    });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (token) {
            authAPI.getMe()
                .then((res) => {
                    setUser(res.data.data);
                    localStorage.setItem('user', JSON.stringify(res.data.data));
                })
                .catch(() => { logout(); })
                .finally(() => setLoading(false));
        } else {
            setLoading(false);
        }
    }, []);

    const setSession = useCallback((token, userData) => {
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
    }, []);

    const login = async (email, password) => {
        const res = await authAPI.login({ email, password });
        const data = res.data.data;

        // MFA required — return the mfa token so the UI can prompt for a code
        if (data.mfaRequired) {
            return { mfaRequired: true, mfaToken: data.mfaToken };
        }

        setSession(data.token, data.user);
        return { mfaRequired: false, user: data.user };
    };

    const completeMfaLogin = async (mfaToken, code) => {
        const res = await authAPI.verifyMfa({ mfaToken, code });
        const data = res.data.data;
        setSession(data.token, data.user);
        return data.user;
    };

    const register = async (data) => {
        const res = await authAPI.register(data);
        return res.data.data;
    };

    const refreshUser = async () => {
        const res = await authAPI.getMe();
        setUser(res.data.data);
        localStorage.setItem('user', JSON.stringify(res.data.data));
        return res.data.data;
    };

    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, login, completeMfaLogin, register, refreshUser, logout, loading }}>
            {children}
        </AuthContext.Provider>
    );
}

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) throw new Error('useAuth must be used within AuthProvider');
    return context;
};
