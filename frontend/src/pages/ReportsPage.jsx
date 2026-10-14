import { useState, useEffect } from 'react';
import { reportAPI, scanAPI } from '../services/api';
import { useToast, PageHeader, StatusBadge, Spinner, Modal, EmptyState, AnimatedNumber, SkeletonRows } from '../components/ui';

/* Icon set — consistent line style, no emoji */
const FormatIcon = ({ format }) => {
    const common = { width: 15, height: 15, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, 'aria-hidden': true };
    if (format === 'html') return <svg {...common}><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z" /></svg>;
    if (format === 'json') return <svg {...common}><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>;
    if (format === 'xml') return <svg {...common}><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg>;
    if (format === 'csv') return <svg {...common}><rect x="3" y="3" width="18" height="18" rx="2" /><line x1="3" y1="9" x2="21" y2="9" /><line x1="3" y1="15" x2="21" y2="15" /><line x1="12" y1="3" x2="12" y2="21" /></svg>;
    return <svg {...common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>;
};

const TemplateIcon = ({ id }) => {
    const common = { width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: '#06B6D4', strokeWidth: 1.6, 'aria-hidden': true };
    if (id === 'executive') return <svg {...common}><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></svg>;
    if (id === 'technical') return <svg {...common}><circle cx="12" cy="12" r="3" /><circle cx="12" cy="12" r="10" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></svg>;
    if (id === 'compliance') return <svg {...common}><path d="M9 11l3 3 8-8" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></svg>;
    if (id === 'html_web') return <svg {...common} stroke="#F97316"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z" /></svg>;
    return <svg {...common}><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>;
};

const FORMAT_CONFIG = {
    pdf:  { label: 'PDF',  color: '#EF4444', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.3)' },
    html: { label: 'HTML', color: '#F97316', bg: 'rgba(249,115,22,0.12)',  border: 'rgba(249,115,22,0.3)' },
    json: { label: 'JSON', color: '#10B981', bg: 'rgba(16,185,129,0.12)',  border: 'rgba(16,185,129,0.3)' },
    xml:  { label: 'XML',  color: '#F59E0B', bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.3)' },
    csv:  { label: 'CSV',  color: '#38BDF8', bg: 'rgba(56,189,248,0.12)',  border: 'rgba(56,189,248,0.3)' },
};

const REPORT_TEMPLATES = [
    { id: 'executive', name: 'Executive Summary', description: 'High-level risk overview for stakeholders and management', format: 'pdf' },
    { id: 'technical', name: 'Technical Deep-Dive', description: 'Full technical details with CVSS scores and remediation guidance', format: 'pdf' },
    { id: 'compliance', name: 'Compliance Report', description: 'OWASP / PCI-DSS / NIST compliance mapping and gap analysis', format: 'pdf' },
    { id: 'html_web', name: 'Interactive Web Report', description: 'Self-contained HTML security assessment report with visual dashboard', format: 'html' },
    { id: 'json_export', name: 'JSON Export', description: 'Machine-readable findings for integration with SIEM / ticketing', format: 'json' },
];

export default function ReportsPage() {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showTemplateModal, setShowTemplateModal] = useState(false);
    const [selectedTemplate, setSelectedTemplate] = useState(null);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState('');
    const [reportTitle, setReportTitle] = useState('');
    const [generating, setGenerating] = useState(false);
    const [generateError, setGenerateError] = useState('');
    const [downloadError, setDownloadError] = useState('');
    const [downloadingId, setDownloadingId] = useState(null);
    const toast = useToast();

    useEffect(() => {
        loadReports();
        scanAPI.list({ status: 'completed' })
            .then(r => setScans(r.data.data || []))
            .catch(() => {});
    }, []);

    const loadReports = () => {
        setLoading(true);
        reportAPI.list()
            .then(r => setReports(r.data.data || []))
            .catch(() => setDownloadError('Could not load reports. Check your connection and try again.'))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        const hasGenerating = reports.some(r => r.status === 'generating');
        if (hasGenerating) {
            const id = setInterval(loadReports, 5000);
            return () => clearInterval(id);
        }
    }, [reports]);

    const handleDownload = async (report) => {
        setDownloadingId(report.id);
        setDownloadError('');
        try {
            const res = await reportAPI.download(report.id);
            const url = URL.createObjectURL(res.data);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${report.title}.${report.format}`;
            // Must append to the DOM for reliable clicks across browsers, and the
            // object URL must NOT be revoked synchronously — Chrome starts the
            // blob download asynchronously and would abort it if the URL is gone.
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            toast('Report downloaded.', 'success');
        } catch (err) {
            setDownloadError(err.response?.data?.error?.message || 'Download failed — the report file may no longer be available. Try regenerating it.');
        } finally { setDownloadingId(null); }
    };

    const handleGenerate = async () => {
        if (!selectedScan || !selectedTemplate) return;
        setGenerating(true);
        setGenerateError('');
        try {
            await reportAPI.create({
                scanId: selectedScan,
                title: reportTitle || `Security Report — ${new Date().toLocaleDateString()}`,
                format: selectedTemplate.format,
                template: selectedTemplate.id,
            });
            setShowTemplateModal(false);
            setSelectedScan('');
            setSelectedTemplate(null);
            setReportTitle('');
            toast('Report generation queued.', 'success');
            loadReports();
        } catch (err) {
            console.error(err);
            setGenerateError(err.response?.data?.error?.message || 'Report generation failed. Please try again.');
        }
        finally { setGenerating(false); }
    };

    const totalReports = reports.length;
    const readyCount = reports.filter(r => r.status === 'completed').length;
    const generatingCount = reports.filter(r => r.status === 'generating').length;

    const openGenerateModal = (template) => {
        setSelectedTemplate(template || null);
        setGenerateError('');
        setShowTemplateModal(true);
    };

    return (
        <div className="animate-fade-in">
            <PageHeader
                kicker="Reporting // Deliverables"
                title="Security Reports"
                subtitle="Turn every scan into an audit-ready document — in one click"
                actions={
                    <button onClick={() => openGenerateModal(null)} className="btn-brand">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        Generate Report
                    </button>
                }
            />

            {/* Summary cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                {[
                    { label: 'Total Reports', value: totalReports, color: '#0891B2' },
                    { label: 'Ready to Download', value: readyCount, color: '#16A34A' },
                    { label: 'Generating', value: generatingCount, color: '#0284C7' },
                ].map(({ label, value, color }) => (
                    <div key={label} className="panel p-5 animate-fade-up">
                        <p className="text-[13px] font-bold text-slate-500 uppercase tracking-[0.08em] mb-2">{label}</p>
                        <p className="text-[34px] font-black leading-none text-white"><AnimatedNumber value={value} /></p>
                    </div>
                ))}
            </div>

            {/* Templates */}
            <div className="panel p-6 mb-6">
                <div className="flex items-center justify-between mb-5">
                    <h2 className="text-[15px] font-bold text-slate-100">Report Templates</h2>
                    <span className="text-[12px] text-slate-500">Select a template to generate a new report</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
                    {REPORT_TEMPLATES.map(template => {
                        const fmt = FORMAT_CONFIG[template.format];
                        return (
                            <button key={template.id}
                                onClick={() => openGenerateModal(template)}
                                className="p-5 rounded-2xl text-left transition-all duration-300 cursor-pointer panel-hover"
                                style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                <div className="text-[22px] mb-3 text-brand-400" aria-hidden="true"><TemplateIcon id={template.id} /></div>
                                <p className="text-[13px] font-bold text-slate-100 mb-1.5">{template.name}</p>
                                <p className="text-[12px] text-slate-500 leading-relaxed mb-4">{template.description}</p>
                                <span className="badge" style={{ color: fmt.color, background: fmt.bg, borderColor: fmt.border }}>{fmt.label}</span>
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* Reports table */}
            {downloadError && (
                <div role="alert" className="mb-5 px-4 py-3 rounded-xl text-[13px] font-medium flex items-center gap-2.5" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.35)', color: '#fca5a5' }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                    <span className="flex-1">{downloadError}</span>
                    <button onClick={() => setDownloadError('')} className="text-slate-400 hover:text-white" aria-label="Dismiss">✕</button>
                </div>
            )}
            <div className="panel-flush">
                <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
                    <h2 className="text-[15px] font-bold text-slate-100">
                        All Reports
                        <span className="ml-2.5 text-[12px] font-semibold text-slate-400 bg-white/[0.06] px-2 py-0.5 rounded-md">{reports.length}</span>
                    </h2>
                </div>

                {loading ? (
                    <table className="w-full" aria-hidden="true">
                        <thead>
                            <tr>{['Report', 'Scan Target', 'Format', 'Status', 'Size', 'Created', 'Actions'].map(h => <th key={h} className="th">{h}</th>)}</tr>
                        </thead>
                        <SkeletonRows rows={4} cols={7} />
                    </table>
                ) : reports.length === 0 ? (
                    <EmptyState
                        title="No reports yet"
                        desc="Create a report from any completed scan and share it with stakeholders."
                        icon={<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>}
                        action={<button onClick={() => openGenerateModal(null)} className="btn-brand">Generate First Report</button>}
                    />
                ) : (
                    <div className="table-scroll">
                    <table className="w-full">
                        <thead>
                            <tr>
                                {['Report', 'Scan Target', 'Format', 'Status', 'Size', 'Created', 'Actions'].map(h => (
                                    <th key={h} className="th">{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {reports.map((report) => {
                                const format = FORMAT_CONFIG[report.format] || { label: report.format?.toUpperCase(), color: '#94A3B8', bg: 'rgba(148,163,184,0.12)', border: 'rgba(148,163,184,0.25)' };
                                return (
                                    <tr key={report.id} className="table-row" style={{ cursor: 'default' }}>
                                        <td className="td">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                                                    style={{ background: format.bg, border: `1px solid ${format.border}`, color: format.color }}>
                                                    <FormatIcon format={report.format} />
                                                </div>
                                                <div>
                                                    <p className="text-[13px] font-bold text-slate-100">{report.title}</p>
                                                    {report.status === 'generating' && (
                                                        <p className="text-[13px] text-blue-400 flex items-center gap-2 mt-1">
                                                            <Spinner size={10} /> Generating report…
                                                        </p>
                                                    )}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="td font-mono text-slate-400 text-[12px]">
                                            {report.scan?.asset?.name || report.scan?.asset?.target || 'N/A'}
                                        </td>
                                        <td className="td">
                                            <span className="badge" style={{ color: format.color, background: format.bg, borderColor: format.border }}>{format.label}</span>
                                        </td>
                                        <td className="td">
                                            <StatusBadge status={report.status === 'completed' ? 'ready' : report.status} />
                                        </td>
                                        <td className="td text-slate-500 text-[12px]">
                                            {report.fileSize ? `${(report.fileSize / 1024).toFixed(1)} KB` : '—'}
                                        </td>
                                        <td className="td text-slate-500 text-[12px]">
                                            {new Date(report.createdAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                                        </td>
                                        <td className="td">
                                            {report.status === 'completed' ? (
                                                <button
                                                    onClick={() => handleDownload(report)}
                                                    disabled={downloadingId === report.id}
                                                    className="btn-brand !px-3.5 !py-1.5 !text-[13px]"
                                                    aria-busy={downloadingId === report.id}
                                                >
                                                    {downloadingId === report.id ? (
                                                        <><Spinner size={11} /> Downloading…</>
                                                    ) : (
                                                        <>
                                                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                                            Download
                                                        </>
                                                    )}
                                                </button>
                                            ) : (
                                                <span className="text-slate-600 text-[12px]">—</span>
                                            )}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                    </div>
                )}
            </div>

            {/* Generate modal */}
            {showTemplateModal && (
                <Modal
                    onClose={() => { setShowTemplateModal(false); setGenerateError(''); }}
                    title="Generate Report"
                    subtitle="Pick a template, target scan, and title"
                    footer={
                        <>
                            <button className="btn-ghost" onClick={() => setShowTemplateModal(false)}>Cancel</button>
                            <button onClick={handleGenerate} disabled={!selectedScan || !selectedTemplate || generating} className="btn-brand" aria-busy={generating}>
                                {generating ? <><Spinner size={14} /> Generating…</> : 'Generate Report'}
                            </button>
                        </>
                    }
                >
                    <div className="mb-5">
                        <p className="field-label mb-3">Report Template</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                            {REPORT_TEMPLATES.map(t => {
                                const active = selectedTemplate?.id === t.id;
                                return (
                                    <button key={t.id} onClick={() => setSelectedTemplate(t)}
                                        className="p-3.5 rounded-xl text-left transition-all duration-200 cursor-pointer"
                                        style={{
                                            border: `1px solid ${active ? 'rgba(6,182,212,0.6)' : 'rgba(255,255,255,0.09)'}`,
                                            background: active ? 'rgba(6,182,212,0.1)' : 'rgba(255,255,255,0.02)',
                                        }}>
                                        <div className="flex items-center gap-2 mb-1.5">
                                            <TemplateIcon id={t.id} />
                                            <span className="text-[13px] font-bold" style={{ color: active ? '#22D3EE' : '#F1F5F9' }}>{t.name}</span>
                                        </div>
                                        <p className="text-[12px] text-slate-400 leading-relaxed">{t.description}</p>
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    <div className="mb-4">
                        <label className="field-label">Select Scan *</label>
                        <select className="select" value={selectedScan} onChange={e => setSelectedScan(e.target.value)}>
                            <option value="">— Select a completed scan —</option>
                            {scans.map(s => (
                                <option key={s.id} value={s.id}>{s.asset?.target || 'N/A'} — {s.scannerType?.toUpperCase()} — {new Date(s.createdAt).toLocaleDateString()}</option>
                            ))}
                        </select>
                    </div>

                    <div>
                        <label className="field-label">Report Title</label>
                        <input
                            className="input"
                            value={reportTitle}
                            onChange={e => setReportTitle(e.target.value)}
                            placeholder="e.g. Q3 2025 Security Assessment"
                        />
                    </div>

                    {generateError && (
                        <div className="mt-4 px-4 py-3 rounded-xl text-[13px] font-medium" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.35)', color: '#fca5a5' }}>
                            <span style={{ marginRight: 6 }}>⚠</span> {generateError}
                        </div>
                    )}
                </Modal>
            )}
        </div>
    );
}
