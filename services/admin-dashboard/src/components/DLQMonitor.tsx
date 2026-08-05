import { useState, useEffect } from 'react';
import { ShieldCheck, AlertOctagon, RefreshCw, Trash2, RotateCcw, ChevronDown, ChevronRight, Clock, FileCode } from 'lucide-react';
import { fetchDeadLetterLogs, retryDeadLetterMessage, purgeDeadLetterMessage, type DeadLetterLog } from '../services/api';

interface DLQMonitorProps {
    activeProjectId: string | null;
    token: string | null;
}

export default function DLQMonitor({ activeProjectId, token }: DLQMonitorProps) {
    const [dlqLogs, setDlqLogs] = useState<DeadLetterLog[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
    const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
    const [feedbackMessage, setFeedbackMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const loadDlqLogs = async () => {
        if (!activeProjectId || !token) {
            setLoading(false);
            return;
        }

        setLoading(true);
        try {
            const logs = await fetchDeadLetterLogs(activeProjectId, token);
            setDlqLogs(logs);
        } catch {
            setDlqLogs([]);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadDlqLogs();
    }, [activeProjectId, token]);

    const handleRetry = async (messageId: string) => {
        if (!token) return;
        setActionLoadingId(messageId);
        setFeedbackMessage(null);
        try {
            await retryDeadLetterMessage(messageId, token);
            setFeedbackMessage({ type: 'success', text: `Message ${messageId.slice(-6)} re-queued into primary threat queue!` });
            await loadDlqLogs();
        } catch (err: any) {
            setFeedbackMessage({ type: 'error', text: err?.message || 'Failed to re-queue message.' });
        } finally {
            setActionLoadingId(null);
        }
    };

    const handlePurge = async (messageId: string) => {
        if (!token) return;
        setActionLoadingId(messageId);
        setFeedbackMessage(null);
        try {
            await purgeDeadLetterMessage(messageId, token);
            setFeedbackMessage({ type: 'success', text: `Poison message ${messageId.slice(-6)} purged from aegis_dead_letter.` });
            await loadDlqLogs();
        } catch (err: any) {
            setFeedbackMessage({ type: 'error', text: err?.message || 'Failed to purge message.' });
        } finally {
            setActionLoadingId(null);
        }
    };

    const toggleExpand = (id: string) => {
        setExpandedLogId(expandedLogId === id ? null : id);
    };

    if (!activeProjectId) {
        return (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
                <AlertOctagon className="w-12 h-12 mx-auto mb-3 text-slate-600 animate-pulse" />
                <h3 className="text-lg font-medium text-slate-200">No Active Project Selected</h3>
                <p className="text-sm mt-1 text-slate-400">Select a project to inspect its Dead-Letter Queue monitoring context.</p>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto space-y-6">
            {/* Header & Stats Banner */}
            <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-5 gap-4">
                <div>
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <AlertOctagon className="w-5 h-5 text-rose-400" />
                        Dead-Letter Queue (DLQ) Monitoring
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                        Inspect unprocessable poison payloads routed to <span className="font-mono text-rose-400">aegis_dead_letter</span> after 3 failed retries.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={loadDlqLogs}
                        disabled={loading}
                        className="px-3.5 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-xs font-medium text-slate-300 transition-colors flex items-center gap-1.5"
                    >
                        <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                        Refresh DLQ
                    </button>
                    <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2 flex items-center gap-3">
                        <div className="text-right">
                            <div className="text-xs text-slate-400 font-medium">Poison Messages</div>
                            <div className={`text-lg font-bold font-mono ${dlqLogs.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                                {dlqLogs.length}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Feedback Alert Banner */}
            {feedbackMessage && (
                <div
                    className={`p-4 rounded-xl border text-sm flex items-center justify-between transition-all ${
                        feedbackMessage.type === 'success'
                            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                            : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
                    }`}
                >
                    <span>{feedbackMessage.text}</span>
                    <button
                        onClick={() => setFeedbackMessage(null)}
                        className="text-xs opacity-70 hover:opacity-100 font-mono underline"
                    >
                        Dismiss
                    </button>
                </div>
            )}

            {/* Loading State */}
            {loading ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 space-y-3">
                    <RefreshCw className="w-8 h-8 mx-auto text-indigo-400 animate-spin" />
                    <p className="text-sm">Fetching Dead-Letter Queue records...</p>
                </div>
            ) : dlqLogs.length === 0 ? (
                /* Empty Healthy State */
                <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-12 text-center space-y-4 shadow-sm">
                    <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center mx-auto text-emerald-400 border border-emerald-500/30">
                        <ShieldCheck className="w-9 h-9" />
                    </div>
                    <div>
                        <span className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs font-semibold text-emerald-400 tracking-wide uppercase">
                            Queue Healthy
                        </span>
                        <h3 className="text-lg font-bold text-white mt-3">No Dead-Lettered Poison Messages</h3>
                        <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                            All threat telemetry packets are processing smoothly without poison message retries in <span className="font-mono text-slate-300">aegis_dead_letter</span>.
                        </p>
                    </div>
                </div>
            ) : (
                /* Log Table View */
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                            <thead>
                                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider">
                                    <th className="py-3.5 px-4 w-8"></th>
                                    <th className="py-3.5 px-4">Timestamp</th>
                                    <th className="py-3.5 px-4">Endpoint / Method</th>
                                    <th className="py-3.5 px-4">Failure Reason</th>
                                    <th className="py-3.5 px-4">Retries</th>
                                    <th className="py-3.5 px-4 text-right">DLQ Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/60 font-sans">
                                {dlqLogs.map((log) => {
                                    const isExpanded = expandedLogId === log._id;
                                    const isLoadingThis = actionLoadingId === log._id;

                                    return (
                                        <tr key={log._id} className="hover:bg-slate-800/40 transition-colors group">
                                            <td className="py-3 px-4 text-slate-500 cursor-pointer" onClick={() => toggleExpand(log._id)}>
                                                {isExpanded ? (
                                                    <ChevronDown className="w-4 h-4 text-indigo-400" />
                                                ) : (
                                                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-slate-300" />
                                                )}
                                            </td>
                                            <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                                                <div className="flex items-center gap-1.5">
                                                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                                                    {new Date(log.timestamp).toLocaleString()}
                                                </div>
                                            </td>
                                            <td className="py-3 px-4 font-mono">
                                                <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-[11px] font-bold text-slate-300 mr-2">
                                                    {log.method || 'POST'}
                                                </span>
                                                <span className="text-slate-300">{log.endpoint || '/unknown'}</span>
                                            </td>
                                            <td className="py-3 px-4 text-rose-400 font-medium">
                                                {log.errorReason || 'Exceeded 3 retries in main broker queue'}
                                            </td>
                                            <td className="py-3 px-4 font-mono">
                                                <span className="px-2 py-0.5 bg-rose-950/60 border border-rose-500/30 rounded text-rose-300">
                                                    {log.retryCount ?? 3}/3
                                                </span>
                                            </td>
                                            <td className="py-3 px-4 text-right space-x-2 whitespace-nowrap">
                                                <button
                                                    onClick={() => handleRetry(log._id)}
                                                    disabled={isLoadingThis}
                                                    title="Re-queue message back to primary security bus"
                                                    className="px-2.5 py-1 bg-indigo-900/40 border border-indigo-500/30 hover:bg-indigo-800/60 text-indigo-300 rounded text-[11px] font-medium transition-colors inline-flex items-center gap-1 disabled:opacity-50"
                                                >
                                                    <RotateCcw className={`w-3 h-3 ${isLoadingThis ? 'animate-spin' : ''}`} />
                                                    Re-queue
                                                </button>
                                                <button
                                                    onClick={() => handlePurge(log._id)}
                                                    disabled={isLoadingThis}
                                                    title="Purge poison message permanently"
                                                    className="px-2.5 py-1 bg-rose-950/40 border border-rose-500/30 hover:bg-rose-900/60 text-rose-300 rounded text-[11px] font-medium transition-colors inline-flex items-center gap-1 disabled:opacity-50"
                                                >
                                                    <Trash2 className="w-3 h-3" />
                                                    Purge
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>

                    {/* Expandable JSON Payload Inspector */}
                    {expandedLogId && (
                        <div className="p-4 bg-slate-950 border-t border-slate-800 font-mono text-xs text-slate-300 space-y-2">
                            <div className="flex items-center justify-between text-slate-400">
                                <span className="flex items-center gap-1.5 text-indigo-400 font-semibold">
                                    <FileCode className="w-4 h-4" />
                                    Raw Poison Payload Content ({expandedLogId})
                                </span>
                                <button onClick={() => setExpandedLogId(null)} className="text-[11px] text-slate-500 hover:text-slate-300">
                                    Close Inspector
                                </button>
                            </div>
                            <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto text-emerald-400">
                                {(() => {
                                    const log = dlqLogs.find((l) => l._id === expandedLogId);
                                    if (!log) return 'No log found';
                                    try {
                                        return JSON.stringify(JSON.parse(log.rawBody || '{}'), null, 2);
                                    } catch {
                                        return log.rawBody || JSON.stringify(log, null, 2);
                                    }
                                })()}
                            </pre>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
