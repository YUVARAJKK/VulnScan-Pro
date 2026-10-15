import { useState, useEffect } from 'react';
import { assetAPI } from '../services/api';
import { PageHeader, GradeBadge, Modal, Spinner, EmptyState, SkeletonRows, useToast } from '../components/ui';

export default function AssetsPage() {
    const [assets, setAssets] = useState([]);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [editing, setEditing] = useState(null);
    const [form, setForm] = useState({ name: '', type: 'ip', target: '', description: '' });
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState('');
    const [deletingId, setDeletingId] = useState(null);
    const toast = useToast();

    const fetchAssets = async () => {
        try {
            const params = {};
            if (search) params.search = search;
            if (typeFilter) params.type = typeFilter;
            const res = await assetAPI.list(params);
            setAssets(res.data.data || []);
            setFetchError('');
        } catch (err) {
            setFetchError(err.response?.data?.error?.message || 'Could not load targets. Check your connection and try again.');
        } finally { setLoading(false); }
    };

    useEffect(() => { fetchAssets(); }, [search, typeFilter]);

    const openCreate = () => { setEditing(null); setForm({ name: '', type: 'ip', target: '', description: '' }); setError(''); setShowModal(true); };
    const openEdit = (a) => { setEditing(a); setForm({ name: a.name, type: a.type, target: a.target, description: a.description || '' }); setError(''); setShowModal(true); };

    const handleSubmit = async (e) => {
        e.preventDefault(); setError('');
        try {
            if (editing) await assetAPI.update(editing.id, form);
            else await assetAPI.create(form);
            setShowModal(false); fetchAssets();
        } catch (err) { setError(err.response?.data?.error?.message || 'Operation failed'); }
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Delete this target? Its scan history will remain.')) return;
        setDeletingId(id);
        try {
            await assetAPI.delete(id);
            toast('Target deleted.', 'info');
            fetchAssets();
        } catch (err) {
            toast(err.response?.data?.error?.message || 'Could not delete the target. Please try again.', 'error');
        } finally { setDeletingId(null); }
    };

    const typeOptions = [
        { value: 'ip', label: 'IP Address' },
        { value: 'domain', label: 'Domain' },
        { value: 'subnet', label: 'Subnet (CIDR)' },
    ];

    return (
        <div className="animate-fade-in">
            <PageHeader
                kicker="Asset Inventory // Targets"
                title="Targets"
                subtitle="The infrastructure you scan, monitor and protect"
                actions={
                    <button onClick={openCreate} className="btn-brand">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        Add Target
                    </button>
                }
            />

            {/* Filters */}
            <div className="flex items-center gap-3 mb-5 flex-wrap">
                <div className="relative">
                    <svg className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    <input
                        className="input pl-10 w-64"
                        placeholder="Search targets…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <select aria-label="Filter by target type" className="select w-44" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                    <option value="">All types</option>
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="subnet">Subnet (CIDR)</option>
                </select>
                <span className="chip ml-auto">{assets.length} target{assets.length !== 1 ? 's' : ''}</span>
            </div>

            {/* Table */}
            <div className="panel-flush">
                {loading ? (
                    <table className="w-full" aria-hidden="true">
                        <thead>
                            <tr>{['Targets', 'Health Score', 'Source / Type', 'Last Scanned', ''].map((h, i) => <th key={i} className="th">{h}</th>)}</tr>
                        </thead>
                        <SkeletonRows rows={4} cols={5} />
                    </table>
                ) : fetchError ? (
                    <div role="alert" className="px-6 py-14">
                        <EmptyState
                            title="Couldn't load targets"
                            desc={fetchError}
                            icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>}
                            action={<button onClick={fetchAssets} className="btn-ghost">Try again</button>}
                        />
                    </div>
                ) : assets.length === 0 ? (
                    <EmptyState
                        title={search || typeFilter ? 'No matching targets' : 'No targets yet'}
                        desc={search || typeFilter ? 'Adjust your search or filters to see more results.' : 'Register your first target to start scanning.'}
                        icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M8 21V7M16 21V12"/></svg>}
                        action={<button onClick={openCreate} className="btn-brand">Add Target</button>}
                    />
                ) : (
                    <div className="table-scroll">
                    <table className="w-full">
                        <thead>
                            <tr>
                                <th className="th">Targets</th>
                                <th className="th">Health Score</th>
                                <th className="th">Source / Type</th>
                                <th className="th">Last Scanned</th>
                                <th className="th w-12"></th>
                            </tr>
                        </thead>
                        <tbody>
                            {assets.map((asset) => (
                                <tr key={asset.id} className="table-row group">
                                    <td className="td">
                                        <div className="flex items-center gap-3">
                                            <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-slate-400 flex-shrink-0">
                                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M8 21V7M16 21V12"/></svg>
                                            </div>
                                            <div>
                                                <p className="text-[13px] font-semibold text-slate-100">{asset.target}</p>
                                                {asset.name && asset.name !== asset.target && (
                                                    <span className="inline-block mt-1 text-[12px] font-bold uppercase px-2 py-0.5 rounded-md bg-brand-500/15 text-brand-300 border border-brand-500/30 tracking-wide">
                                                        {asset.name}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </td>
                                    <td className="td">
                                        {asset.healthGrade ? (
                                            <GradeBadge grade={asset.healthGrade} score={asset.healthScore || 0} />
                                        ) : (
                                            <span className="text-slate-500 text-[12px]">—</span>
                                        )}
                                    </td>
                                    <td className="td">
                                        <span className="chip">
                                            <span className="w-1.5 h-1.5 rounded-full bg-brand-400" aria-hidden="true" />
                                            {typeOptions.find(t => t.value === asset.type)?.label || asset.type || 'Manual'}
                                        </span>
                                    </td>
                                    <td className="td">
                                        {asset.lastScanAt ? (
                                            <span className="text-[13px] text-slate-400 flex items-center gap-1.5">
                                                {new Date(asset.lastScanAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#71717A" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                                            </span>
                                        ) : (
                                            <span className="text-slate-500 text-[12px]">Never</span>
                                        )}
                                    </td>
                                    <td className="td">
                                        <div className="flex gap-1.5 justify-end md:opacity-0 md:group-hover:opacity-100 md:group-focus-within:opacity-100 transition-opacity">
                                            <button onClick={() => openEdit(asset)} className="btn-soft !px-2.5 !py-1.5" title="Edit target" aria-label={`Edit ${asset.target}`} disabled={deletingId === asset.id}>
                                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/></svg>
                                            </button>
                                            <button onClick={() => handleDelete(asset.id)} className="btn-danger !px-2.5 !py-1.5" title="Delete target" aria-label={`Delete ${asset.target}`} disabled={deletingId === asset.id} aria-busy={deletingId === asset.id}>
                                                {deletingId === asset.id ? <Spinner size={11} /> : (
                                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                                )}
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    </div>
                )}

                {assets.length > 0 && (
                    <div className="px-5 py-3.5 flex items-center justify-between text-[12px] text-slate-500 border-t border-white/[0.05]">
                        <span>{assets.length} target{assets.length !== 1 ? 's' : ''}</span>
                        {search || typeFilter ? (
                            <button onClick={() => { setSearch(''); setTypeFilter(''); }} className="text-brand-400 hover:text-brand-300 font-semibold">Clear filters</button>
                        ) : <span />}
                    </div>
                )}
            </div>

            {/* Modal */}
            {showModal && (
                <Modal
                    onClose={() => setShowModal(false)}
                    title={editing ? 'Edit Target' : 'Add Target'}
                    subtitle={editing ? `Update ${editing.target}` : 'Register a new scan target'}
                    footer={
                        <>
                            <button className="btn-ghost" onClick={() => setShowModal(false)}>Cancel</button>
                            <button type="submit" form="asset-form" className="btn-brand">
                                {editing ? 'Update Target' : 'Create Target'}
                            </button>
                        </>
                    }
                >
                    {error && <div role="alert" className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/25 text-red-300 text-[13px]">{error}</div>}
                    <form id="asset-form" onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="field-label" htmlFor="asset-name">Name</label>
                            <input id="asset-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required autoFocus />
                        </div>
                        <div>
                            <label className="field-label" htmlFor="asset-type">Type</label>
                            <select id="asset-type" className="select" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                                {typeOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className="field-label" htmlFor="asset-target">Target</label>
                            <input
                                id="asset-target"
                                className="input font-mono"
                                placeholder={form.type === 'ip' ? '192.168.1.100' : form.type === 'domain' ? 'example.com' : '192.168.1.0/24'}
                                value={form.target}
                                onChange={(e) => setForm({ ...form, target: e.target.value })}
                                required
                            />
                        </div>
                        <div>
                            <label className="field-label" htmlFor="asset-desc">Description <span className="text-slate-600 font-normal">(optional)</span></label>
                            <input id="asset-desc" className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                        </div>
                    </form>
                </Modal>
            )}
        </div>
    );
}
