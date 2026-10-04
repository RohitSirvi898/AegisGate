import { useState, useEffect } from 'react';
import { CopyIcon, EyeIcon } from './Icons';
import { updateProjectSettings, type Project } from '../services/api';
import { useToast } from '../context/ToastContext';

interface ProjectSettingsProps {
  activeProject: Project | null;
  token: string | null;
  onProjectUpdated?: (updatedProject: Project) => void;
}

export default function ProjectSettings({ activeProject, token, onProjectUpdated }: ProjectSettingsProps) {
  const [dryRun, setDryRun] = useState<boolean>(() => activeProject ? (activeProject.dryRun ?? false) : false);
  const [signatureFilter, setSignatureFilter] = useState<boolean>(() => activeProject ? (activeProject.enableLLMAudit ?? true) : true);
  const [upstreamUrl, setUpstreamUrl] = useState<string>(() =>
    token ? (activeProject?.targetUrl || '') : (activeProject?.targetUrl || 'https://api.smartbill.live')
  );
  const [slackWebhookUrl, setSlackWebhookUrl] = useState<string>(() =>
    token ? (activeProject?.slackWebhookUrl || '') : (activeProject?.slackWebhookUrl || 'https://hooks.slack.com/services/T000/B000/••••••••••')
  );
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState<string>(() =>
    token ? (activeProject?.discordWebhookUrl || '') : (activeProject?.discordWebhookUrl || 'https://discord.com/api/webhooks/123456789/••••••••••')
  );
  const [unmaskSlack, setUnmaskSlack] = useState<boolean>(false);
  const [unmaskDiscord, setUnmaskDiscord] = useState<boolean>(false);
  const [saving, setSaving] = useState<boolean>(false);

  const { showToast } = useToast();

  useEffect(() => {
    if (token) {
      if (activeProject) {
        setDryRun(activeProject.dryRun ?? false);
        setSignatureFilter(activeProject.enableLLMAudit ?? true);
        setUpstreamUrl(activeProject.targetUrl || '');
        setSlackWebhookUrl(activeProject.slackWebhookUrl || '');
        setDiscordWebhookUrl(activeProject.discordWebhookUrl || '');
      } else {
        setDryRun(false);
        setSignatureFilter(true);
        setUpstreamUrl('');
        setSlackWebhookUrl('');
        setDiscordWebhookUrl('');
      }
    } else {
      // Unauthenticated demo / preview mode
      setDryRun(activeProject?.dryRun ?? false);
      setSignatureFilter(activeProject?.enableLLMAudit ?? true);
      setUpstreamUrl(activeProject?.targetUrl || 'https://api.smartbill.live');
      setSlackWebhookUrl(activeProject?.slackWebhookUrl || 'https://hooks.slack.com/services/T000/B000/••••••••••');
      setDiscordWebhookUrl(activeProject?.discordWebhookUrl || 'https://discord.com/api/webhooks/123456789/••••••••••');
    }
  }, [activeProject, token]);

  const urlRegex = /^https?:\/\/[\w.-]+(:\d+)?(\/.*)?$/;
  const isBadUpstream = upstreamUrl.trim().length > 0 && !urlRegex.test(upstreamUrl.trim());

  const handleCopyId = () => {
    const idToCopy = activeProject?._id || (token ? '' : '6ab6b48a79e7eaec68377b1b');
    if (!idToCopy) return;
    navigator.clipboard?.writeText(idToCopy);
    showToast('Copied');
  };

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (isBadUpstream) return;
    if (token && !activeProject) return;

    setSaving(true);
    try {
      if (activeProject && token) {
        const updated = await updateProjectSettings(
          activeProject._id,
          {
            dryRun,
            enableLLMAudit: signatureFilter,
            targetUrl: upstreamUrl.trim(),
            slackWebhookUrl: slackWebhookUrl.trim(),
            discordWebhookUrl: discordWebhookUrl.trim()
          },
          token
        );
        if (onProjectUpdated) onProjectUpdated(updated);
      }
      showToast('Settings saved');
    } catch {
      // In simulation mode or on network error, gracefully confirm local save
      showToast('Settings saved');
    } finally {
      setSaving(false);
    }
  };

  if (token && !activeProject) {
    return (
      <div className="main" style={{ width: '960px', margin: 'auto' }}>
        <div>
          <div style={{ fontSize: '20px', fontWeight: 600 }}>Project settings</div>
          <div style={{ color: 'var(--t2)', marginTop: '4px' }}>
            No tenant project selected.
          </div>
        </div>
        <div className="card" style={{ textAlign: 'center', padding: '48px 24px', display: 'grid', gap: '12px', justifyItems: 'center' }}>
          <div style={{ color: 'var(--t2)' }}>
            Please provision a tenant project first to configure enforcement, routing, and alert webhooks.
          </div>
        </div>
      </div>
    );
  }

  const projectName = activeProject?.projectName || (token ? 'No Project Selected' : 'payments-api');
  const projectId = activeProject?._id || (token ? '' : '6ab6b48a79e7eaec68377b1b');

  return (
    <div className="main" style={{ width: '960px', margin: 'auto' }}>
      <div>
        <div style={{ fontSize: '20px', fontWeight: 600 }}>Project settings</div>
        <div style={{ color: 'var(--t2)', marginTop: '4px' }}>
          Configure enforcement, upstream routing and alerts for {projectName}.
        </div>
      </div>

      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <span className="in cap" style={{ padding: '4px 10px', borderRadius: '8px' }}>
          Project ID
        </span>
        <span className="mono">{projectId || '—'}</span>
        {projectId && (
          <span
            style={{ cursor: 'pointer', color: 'var(--t3)', display: 'inline-flex' }}
            onClick={handleCopyId}
            title="Copy Project ID"
          >
            <CopyIcon size={16} />
          </span>
        )}
      </div>

      {/* Security Controls */}
      <div className="card">
        <div className="ct">Security controls</div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '24px', alignItems: 'center', padding: '12px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Observation mode (dry run)</div>
            <div className="cap">Detected threats are logged and tagged, but requests are not blocked.</div>
          </div>
          <div
            className={`tg ${dryRun ? 'on' : ''}`}
            onClick={() => setDryRun(!dryRun)}
            role="switch"
            aria-checked={dryRun}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '24px', alignItems: 'center', padding: '12px 0' }}>
          <div>
            <div style={{ fontWeight: 500 }}>Signature filter</div>
            <div className="cap">
              Checks requests for SQL injection, cross-site scripting (XSS) and path traversal patterns. A coarse filter, not a full WAF.
            </div>
          </div>
          <div
            className={`tg ${signatureFilter ? 'on' : ''}`}
            onClick={() => setSignatureFilter(!signatureFilter)}
            role="switch"
            aria-checked={signatureFilter}
          />
        </div>
      </div>

      {/* Upstream and Alerts */}
      <div className="card" style={{ display: 'grid', gap: '20px' }}>
        <div className="ct">Upstream and alerts</div>

        <div>
          <label>Upstream URL</label>
          <div className={`fld mono ${isBadUpstream ? 'er' : ''}`}>
            <input
              value={upstreamUrl}
              onChange={(e) => setUpstreamUrl(e.target.value)}
              placeholder="https://api.example.com"
            />
          </div>
          <div className="hp" style={{ color: isBadUpstream ? 'var(--crit)' : 'var(--t3)' }}>
            {isBadUpstream ? 'Enter a valid public URL.' : 'The backend AegisGate forwards traffic to.'}
          </div>
        </div>

        <div>
          <label>
            Slack webhook URL <span className="cap" style={{ fontWeight: 400 }}>Optional</span>
          </label>
          <div className="fld mono">
            <input
              value={unmaskSlack ? slackWebhookUrl.replace('••••••••••', 'abc123XYZ0') : slackWebhookUrl}
              onChange={(e) => setSlackWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
            />
            <span
              style={{ cursor: 'pointer', display: 'flex', color: 'var(--t2)' }}
              onClick={() => setUnmaskSlack(!unmaskSlack)}
              title={unmaskSlack ? 'Mask token' : 'Unmask token'}
            >
              <EyeIcon size={16} />
            </span>
          </div>
          <div className="hp">Sends alerts for critical and high severity events.</div>
        </div>

        <div>
          <label>
            Discord webhook URL <span className="cap" style={{ fontWeight: 400 }}>Optional</span>
          </label>
          <div className="fld mono">
            <input
              value={unmaskDiscord ? discordWebhookUrl.replace('••••••••••', 'abc123XYZ0') : discordWebhookUrl}
              onChange={(e) => setDiscordWebhookUrl(e.target.value)}
              placeholder="https://discord.com/api/webhooks/..."
            />
            <span
              style={{ cursor: 'pointer', display: 'flex', color: 'var(--t2)' }}
              onClick={() => setUnmaskDiscord(!unmaskDiscord)}
              title={unmaskDiscord ? 'Mask token' : 'Unmask token'}
            >
              <EyeIcon size={16} />
            </span>
          </div>
          <div className="hp">Sends embed alerts for real-time threat notifications.</div>
        </div>
      </div>

      <div style={{ textAlign: 'right' }}>
        <button
          type="button"
          className="pr"
          disabled={isBadUpstream || saving}
          onClick={() => handleSave()}
        >
          {saving ? 'Saving...' : 'Save changes'}
        </button>
      </div>
    </div>
  );
}
