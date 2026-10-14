import { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { PageHeader, Spinner, EmptyState, Avatar, SkeletonRows, useToast } from '../components/ui';

export default function AdminPage() {
    const [tab, setTab] = useState('users');
    const [users, setUsers] = useState([]);
    const [auditLogs, setAuditLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const toast = useToast();

    useEffect(() => {
        setLoading(true);
        if (tab === 'users') {
            adminAPI.getUsers().then(r => setUsers(r.data.data)).catch(console.error).finally(() => setLoading(false));
        } else {
            adminAPI.getAuditLogs().then(r => setAuditLogs(r.data.data)).catch(console.error).finally(() => setLoading(false));
        }
    }, [tab]);

    const handleRoleChange = async (userId, role) => {
        try {
            await adminAPI.updateUser(userId, { role });
            toast('Role updated.', 'success');
            const r = await adminAPI.getUsers();
            setUsers(r.data.data);
        } catch (err) {
            toast(err.response?.data?.error?.message || 'Could not update the user role.', 'error');
        }
    };

    const handleToggleActive = async (userId, isActive) => {
        try {
            await adminAPI.updateUser(userId, { isActive: !isActive });
            toast(isActive ? 'User deactivated.' : 'User activated.', 'success');
            const r = await adminAPI.getUsers();
            setUsers(r.data.data);
        } catch (err) {
            toast(err.response?.data?.error?.message || 'Could not update the user status.', 'error');
        }
    };

    return (
        <div className="animate-fade-in">
            <PageHeader
                kicker="Administration // Access Control"
                title="Settings"
                subtitle="People, permissions and a complete audit trail"
            />

            {/* Tabs — segmented control in the brand palette */}
            <div role="tablist" aria-label="Settings sections" className="flex gap-1.5 mb-6 w-fit p-1.5 rounded-2xl bg-white/[0.03] border border-white/[0.07]">
                {[['users', 'Users'], ['audit', 'Audit Logs']].map(([key, label]) => (
                    <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                        className="px-5 py-2.5 rounded-xl text-[13px] font-semibold transition-all duration-200 cursor-pointer"
                        style={{
                            background: tab === key ? 'linear-gradient(135deg, rgba(6,182,212,0.25), rgba(8,145,178,0.2))' : 'transparent',
                            color: tab === key ? '#0E7490' : '#64748B',
                            boxShadow: tab === key ? 'inset 0 1px 0 rgba(255,255,255,0.08), 0 2px 12px rgba(6,182,212,0.15)' : 'none',
                        }}>
                        {label}
                    </button>
                ))}
            </div>

            {loading && (
                <div className="panel-flush">
                    <table className="w-full" aria-hidden="true">
                        <thead><tr>{['Name', 'Email', 'Role', 'Status', 'Joined', 'Actions'].map(h => <th key={h} className="th">{h}</th>)}</tr></thead>
                        <SkeletonRows rows={4} cols={6} />
                    </table>
                </div>
            )}

            {/* Users */}
            {!loading && tab === 'users' && (
                <div className="panel-flush animate-fade-up">
                    {users.length === 0 ? (
                        <EmptyState title="No users found" desc="Invite users to collaborate on scanning operations." icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>} />
                    ) : (
                        <div className="table-scroll">
                        <table className="w-full">
                            <thead>
                                <tr>
                                    {['Name', 'Email', 'Role', 'Status', 'Joined', 'Actions'].map(h => <th key={h} className="th">{h}</th>)}
                                </tr>
                            </thead>
                            <tbody>
                                {users.map((u) => {
                                    const fullName = `${u.firstName} ${u.lastName}`.trim();
                                    return (
                                        <tr key={u.id} className="table-row" style={{ cursor: 'default' }}>
                                            <td className="td">
                                                <div className="flex items-center gap-3">
                                                    <Avatar name={fullName} size={34} />
                                                    <span className="text-[13px] font-semibold text-slate-100">{fullName || '—'}</span>
                                                </div>
                                            </td>
                                            <td className="td text-slate-400">{u.email}</td>
                                            <td className="td">
                                                <select
                                                    aria-label={`Role for ${fullName || u.email}`}
                                                    className="select !w-auto !py-1.5 !px-3 !text-[12px]"
                                                    value={u.role}
                                                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                                                >
                                                    <option value="viewer">Viewer</option>
                                                    <option value="analyst">Analyst</option>
                                                    <option value="admin">Admin</option>
                                                </select>
                                            </td>
                                            <td className="td">
                                                <span className="badge" style={{
                                                    color: u.isActive ? '#34D399' : '#F87171',
                                                    background: u.isActive ? 'rgba(52,211,153,0.12)' : 'rgba(248,113,113,0.12)',
                                                    borderColor: u.isActive ? 'rgba(52,211,153,0.3)' : 'rgba(248,113,113,0.3)',
                                                }}>
                                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: u.isActive ? '#34D399' : '#F87171' }} />
                                                    {u.isActive ? 'Active' : 'Inactive'}
                                                </span>
                                            </td>
                                            <td className="td text-slate-500">{new Date(u.createdAt).toLocaleDateString()}</td>
                                            <td className="td">
                                                <button
                                                    onClick={() => handleToggleActive(u.id, u.isActive)}
                                                    className={`${u.isActive ? 'btn-danger' : 'btn-soft'} !px-3 !py-1.5 !text-[13px]`}
                                                >
                                                    {u.isActive ? 'Deactivate' : 'Activate'}
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                        </div>
                    )}
                </div>
            )}

            {/* Audit logs */}
            {!loading && tab === 'audit' && (
                <div className="panel-flush animate-fade-up">
                    {auditLogs.length === 0 ? (
                        <EmptyState title="No audit logs found" desc="Security events will appear here as they occur." icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>} />
                    ) : (
                        <div className="table-scroll">
                        <table className="w-full">
                            <thead>
                                <tr>
                                    {['User', 'Action', 'Resource', 'IP', 'Timestamp'].map(h => <th key={h} className="th">{h}</th>)}
                                </tr>
                            </thead>
                            <tbody>
                                {auditLogs.map((log) => (
                                    <tr key={log.id} className="table-row" style={{ cursor: 'default' }}>
                                        <td className="td text-slate-100">{log.user?.firstName} {log.user?.lastName}</td>
                                        <td className="td">
                                            <span className="chip font-mono !text-[12px] !bg-brand-500/10 !border-brand-500/25 !text-brand-300">{log.action}</span>
                                        </td>
                                        <td className="td text-slate-400">{log.resourceType}{log.resourceId ? ` (${log.resourceId.slice(0, 8)}…)` : ''}</td>
                                        <td className="td font-mono text-slate-400">{log.ipAddress || '—'}</td>
                                        <td className="td text-slate-500">{new Date(log.createdAt).toLocaleString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
