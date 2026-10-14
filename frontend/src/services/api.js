import axios from 'axios';

const api = axios.create({
    baseURL: '/api/v1',
    headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
});

// Handle 401 responses globally
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// ─── Auth ───
export const authAPI = {
    register: (data) => api.post('/auth/register', data),
    verifyEmail: (token) => api.post('/auth/verify-email', { token }),
    resendVerification: (email) => api.post('/auth/resend-verification', { email }),
    login: (data) => api.post('/auth/login', data),
    verifyMfa: (data) => api.post('/auth/mfa/verify', data),
    mfaSetup: () => api.post('/auth/mfa/setup'),
    mfaEnable: (code) => api.post('/auth/mfa/enable', { code }),
    mfaDisable: (code) => api.post('/auth/mfa/disable', { code }),
    forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
    resetPassword: (data) => api.post('/auth/reset-password', data),
    getMe: () => api.get('/auth/me'),
    updateProfile: (data) => api.put('/auth/profile', data),
    changePassword: (data) => api.put('/auth/password', data),
};

// ─── Assets ───
export const assetAPI = {
    list: (params) => api.get('/assets', { params }),
    get: (id) => api.get(`/assets/${id}`),
    create: (data) => api.post('/assets', data),
    update: (id, data) => api.put(`/assets/${id}`, data),
    delete: (id) => api.delete(`/assets/${id}`),
};

// ─── Scans ───
export const scanAPI = {
    list: (params) => api.get('/scans', { params }),
    get: (id) => api.get(`/scans/${id}`),
    create: (data) => api.post('/scans', data),
    cancel: (id) => api.post(`/scans/${id}/cancel`),
    retry: (id) => api.post(`/scans/${id}/retry`),
    getVulnerabilities: (id, params) => api.get(`/scans/${id}/vulnerabilities`, { params }),
    exportScan: (id, format) => api.get(`/scans/${id}/export`, { params: { format }, responseType: format === 'csv' ? 'blob' : 'json' }),
    toggleSchedule: (id, data) => api.put(`/scans/${id}/schedule`, data),
    updateVulnStatus: (id, status) => api.patch(`/scans/vulnerabilities/${id}/status`, { status }),
    getAiRemediation: (vulnId) => api.get(`/scans/vulnerabilities/${vulnId}/ai-remediation`),
};

// ─── Reports ───
export const reportAPI = {
    list: (params) => api.get('/reports', { params }),
    get: (id) => api.get(`/reports/${id}`),
    create: (data) => api.post('/reports', data),
    download: (id) => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
};

// ─── Dashboard ───
export const dashboardAPI = {
    getStats: () => api.get('/dashboard/stats'),
    getAdminStats: () => api.get('/dashboard/admin'),
};

// ─── Admin ───
export const adminAPI = {
    getUsers: (params) => api.get('/admin/users', { params }),
    updateUser: (id, data) => api.put(`/admin/users/${id}`, data),
    getAuditLogs: (params) => api.get('/admin/audit-logs', { params }),
};

// ─── Public Scan (no auth required) ───
const publicApi = axios.create({
    baseURL: '/api/v1',
    headers: { 'Content-Type': 'application/json' },
});

export const publicScanAPI = {
    submit: (data) => publicApi.post('/public/scan', data),
    getByToken: (token) => publicApi.get(`/public/scan/${token}`),
    getStatus: (token) => publicApi.get(`/public/scan/${token}/status`),
    exportPdf: (token) => publicApi.get(`/public/scan/${token}/export/pdf`, { responseType: 'blob' }),
    exportXml: (token) => publicApi.get(`/public/scan/${token}/export/xml`, { responseType: 'blob' }),
    exportJson: (token) => publicApi.get(`/public/scan/${token}/export/json`),
};

export default api;

