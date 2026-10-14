import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './store/AuthContext';
import { ToastProvider } from './components/ui';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import VerifyEmailPage from './pages/VerifyEmailPage';
import DashboardPage from './pages/DashboardPage';
import AssetsPage from './pages/AssetsPage';
import ScansPage from './pages/ScansPage';
import ScanDetailPage from './pages/ScanDetailPage';
import ReportsPage from './pages/ReportsPage';
import ProfilePage from './pages/ProfilePage';
import AdminPage from './pages/AdminPage';
import LandingPage from './pages/LandingPage';
import PublicReportPage from './pages/PublicReportPage';

function PrivateRoute({ children, requiredRole }) {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen app-bg">
                <div className="h-12 w-12 rounded-full border-2 animate-spin-slow" style={{ borderColor: 'rgba(8,145,178,0.2)', borderTopColor: '#0891B2' }}></div>
            </div>
        );
    }

    if (!user) return <Navigate to="/login" />;

    if (requiredRole) {
        const hierarchy = { admin: 3, analyst: 2, viewer: 1 };
        if ((hierarchy[user.role] || 0) < (hierarchy[requiredRole] || 0)) {
            return <Navigate to="/app/dashboard" />;
        }
    }

    return children;
}

export default function App() {
    return (
        <AuthProvider>
            <ToastProvider>
            <BrowserRouter>
                <Routes>
                    {/* Public Routes (no auth) */}
                    <Route path="/" element={<LandingPage />} />
                    <Route path="/login" element={<LoginPage />} />
                    <Route path="/register" element={<RegisterPage />} />
                    <Route path="/forgot-password" element={<ForgotPasswordPage />} />
                    <Route path="/reset-password" element={<ResetPasswordPage />} />
                    <Route path="/verify-email" element={<VerifyEmailPage />} />
                    <Route path="/report/:token" element={<PublicReportPage />} />

                    {/* Protected Routes (auth required) */}
                    <Route path="/app" element={<PrivateRoute><Layout /></PrivateRoute>}>
                        <Route index element={<Navigate to="/app/dashboard" />} />
                        <Route path="dashboard" element={<DashboardPage />} />
                        <Route path="assets" element={<PrivateRoute requiredRole="analyst"><AssetsPage /></PrivateRoute>} />
                        <Route path="scans" element={<ScansPage />} />
                        <Route path="scans/:id" element={<ScanDetailPage />} />
                        <Route path="reports" element={<ReportsPage />} />
                        <Route path="profile" element={<ProfilePage />} />
                        <Route path="admin" element={<PrivateRoute requiredRole="admin"><AdminPage /></PrivateRoute>} />
                    </Route>

                    {/* Catch-all */}
                    <Route path="*" element={<Navigate to="/" />} />
                </Routes>
            </BrowserRouter>
            </ToastProvider>
        </AuthProvider>
    );
}
