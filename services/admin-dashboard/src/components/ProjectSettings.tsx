import { useState, useEffect } from 'react';
import { Settings, Shield, Bell, CheckCircle, AlertCircle, RefreshCw, Lock, ExternalLink, Activity } from 'lucide-react';
import { updateProjectSettings, type Project } from '../services/api';

interface ProjectSettingsProps {
    activeProject: Project | null;
    token: string | null;
    onProjectUpdated?: (updatedProject: Project) => void;
}

export default function ProjectSettings({ activeProject, token, onProjectUpdated }: ProjectSettingsProps) {
    const [dryRun, setDryRun] = useState<boolean>(true);
    const [enableLLMAudit, setEnableLLMAudit] = useState<boolean>(true);
    const [slackWebhookUrl, setSlackWebhookUrl] = useState<string>('');
    const [discordWebhookUrl, setDiscordWebhookUrl] = useState<string>('');
    const [targetUrl, setTargetUrl] = useState<string>('');
    
    const [loading, setLoading] = useState<boolean>(false);
    const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    useEffect(() => {
        if (activeProject) {
            setDryRun(activeProject.dryRun ?? true);
            setEnableLLMAudit(activeProject.enableLLMAudit ?? true);
            setSlackWebhookUrl(activeProject.slackWebhookUrl || '');
            setDiscordWebhookUrl(activeProject.discordWebhookUrl || '');
            setTargetUrl(activeProject.targetUrl || '');
        }
    }, [activeProject]);

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!activeProject || !token) {
            setStatusMessage({ type: 'error', text: 'No active project selected or invalid session token.' });
            return;
        }

        setLoading(true);
        setStatusMessage(null);

        try {
            const updated = await updateProjectSettings(
                activeProject._id,
                {
                    dryRun,
                    enableLLMAudit,
                    slackWebhookUrl,
                    discordWebhookUrl,
                    targetUrl
                },
                token
            );

            setStatusMessage({ type: 'success', text: 'Project settings updated and synchronized across Gateway nodes!' });
            if (onProjectUpdated) {
                onProjectUpdated(updated);
            }
        } catch (err: any) {
            setStatusMessage({ type: 'error', text: err?.message || 'Failed to save project settings.' });
        } finally {
            setLoading(false);
        }
    };

    if (!activeProject) {
        return (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
                <Settings className="w-12 h-12 mx-auto mb-3 text-slate-600 animate-pulse" />
                <h3 className="text-lg font-medium text-slate-200">No Active Project Selected</h3>
                <p className="text-sm mt-1 text-slate-400">Please select or provision a tenant project to manage its security controls.</p>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            {/* Header Title */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-5">
                <div>
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <Settings className="w-5 h-5 text-indigo-400" />
                        Project Settings & Protection Controls
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                        Configure enforcement modes, privacy thresholds, and real-time security webhooks for <span className="text-indigo-400 font-mono">{activeProject.projectName}</span>.
                    </p>
                </div>
                <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>ID: {activeProject._id}</span>
                </div>
            </div>

            {/* Status Alert Banner */}
            {statusMessage && (
                <div
                    className={`p-4 rounded-xl border text-sm flex items-start gap-3 transition-all ${
                        statusMessage.type === 'success'
                            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                            : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
                    }`}
                >
                    {statusMessage.type === 'success' ? (
                        <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                        <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                    )}
                    <div>
                        <p className="font-medium">{statusMessage.text}</p>
                    </div>
                </div>
            )}

            <form onSubmit={handleSave} className="space-y-6">
                {/* Mode & Privacy Toggles */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6 shadow-sm">
                    <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-indigo-400" />
                        Security Boundary Controls
                    </h3>

                    {/* Dry-Run Toggle */}
                    <div className="flex items-start justify-between p-4 bg-slate-950 border border-slate-800/80 rounded-xl hover:border-slate-700 transition-colors">
                        <div className="space-y-1 pr-4">
                            <label htmlFor="dryRunToggle" className="text-sm font-medium text-white cursor-pointer flex items-center gap-2">
                                Enable Dry-Run / Observation Mode (Logs threats without blocking 403s)
                            </label>
                            <p className="text-xs text-slate-400">
                                When enabled, structural anomalies trigger live telemetry logging and header tags without dropping user HTTP connections.
                            </p>
                        </div>
                        <button
                            id="dryRunToggle"
                            type="button"
                            role="switch"
                            aria-checked={dryRun}
                            onClick={() => setDryRun(!dryRun)}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                dryRun ? 'bg-indigo-600' : 'bg-slate-700'
                            }`}
                        >
                            <span
                                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                                    dryRun ? 'translate-x-5' : 'translate-x-0'
                                }`}
                            />
                        </button>
                    </div>

                    {/* LLM Privacy Toggle */}
                    <div className="flex items-start justify-between p-4 bg-slate-950 border border-slate-800/80 rounded-xl hover:border-slate-700 transition-colors">
                        <div className="space-y-1 pr-4">
                            <label htmlFor="enableLLMAuditToggle" className="text-sm font-medium text-white cursor-pointer flex items-center gap-2">
                                Enable AI LLM Threat Analysis (Disable to prevent sending scrubbed payloads to external Gemini LLM)
                            </label>
                            <p className="text-xs text-slate-400">
                                Opt-out of external AI LLM categorization. Threats will be scrubbed and logged directly as <span className="font-mono text-amber-400">UNANALYZED_PRIVACY_OPT_OUT</span>.
                            </p>
                        </div>
                        <button
                            id="enableLLMAuditToggle"
                            type="button"
                            role="switch"
                            aria-checked={enableLLMAudit}
                            onClick={() => setEnableLLMAudit(!enableLLMAudit)}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                enableLLMAudit ? 'bg-emerald-600' : 'bg-slate-700'
                            }`}
                        >
                            <span
                                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                                    enableLLMAudit ? 'translate-x-5' : 'translate-x-0'
                                }`}
                            />
                        </button>
                    </div>
                </div>

                {/* Target URL & Webhook Configuration */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6 shadow-sm">
                    <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                        <Bell className="w-4 h-4 text-indigo-400" />
                        Upstream Routing & Real-Time Alerts
                    </h3>

                    {/* Target Backend URL */}
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                            <Activity className="w-3.5 h-3.5 text-indigo-400" />
                            Upstream Target Backend URL
                        </label>
                        <input
                            type="url"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            placeholder="http://localhost:3000"
                            className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 font-mono focus:outline-none focus:border-indigo-500 transition-colors"
                        />
                        <p className="text-[11px] text-slate-500">The destination microservice backend that AegisGate proxies traffic to.</p>
                    </div>

                    {/* Slack Webhook URL */}
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                            <ExternalLink className="w-3.5 h-3.5 text-emerald-400" />
                            Slack Webhook URL
                        </label>
                        <input
                            type="url"
                            value={slackWebhookUrl}
                            onChange={(e) => setSlackWebhookUrl(e.target.value)}
                            placeholder="https://hooks.slack.com/services/T000/B000/XXXX"
                            className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 font-mono focus:outline-none focus:border-indigo-500 transition-colors"
                        />
                        <p className="text-[11px] text-slate-500">Dispatches Slack Block Kit security alerts for CRITICAL and HIGH severity anomalies.</p>
                    </div>

                    {/* Discord Webhook URL */}
                    <div className="space-y-2">
                        <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                            <ExternalLink className="w-3.5 h-3.5 text-indigo-400" />
                            Discord Webhook URL
                        </label>
                        <input
                            type="url"
                            value={discordWebhookUrl}
                            onChange={(e) => setDiscordWebhookUrl(e.target.value)}
                            placeholder="https://discord.com/api/webhooks/123456789/XXXXX"
                            className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 font-mono focus:outline-none focus:border-indigo-500 transition-colors"
                        />
                        <p className="text-[11px] text-slate-500">Dispatches Discord Embed cards for real-time threat notifications.</p>
                    </div>
                </div>

                {/* Submit Button */}
                <div className="flex justify-end pt-2">
                    <button
                        type="submit"
                        disabled={loading}
                        className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition-all shadow-lg shadow-indigo-600/20 disabled:opacity-50 flex items-center gap-2"
                    >
                        {loading ? (
                            <>
                                <RefreshCw className="w-4 h-4 animate-spin" />
                                Saving Changes...
                            </>
                        ) : (
                            <>
                                <CheckCircle className="w-4 h-4" />
                                Save Project Controls
                            </>
                        )}
                    </button>
                </div>
            </form>
        </div>
    );
}
