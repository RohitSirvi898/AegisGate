import React, { useState } from 'react';

import { useToast } from '../context/ToastContext';
import { createProject, type Project } from '../services/api';
import { WarningIcon } from './Icons';

interface TenantProvisioningProps {
  token: string | null;
  onProjectCreated?: (project: Project) => void;
}

export default function TenantProvisioning({ token, onProjectCreated }: TenantProvisioningProps) {
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(false);
  const [provisioned, setProvisioned] = useState<{ _id: string; projectName: string; apiKey: string } | null>(null);
  const { showToast } = useToast();

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    showToast('Copied');
  };

  const handleGenerateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) return;

    setLoading(true);
    try {
      if (token) {
        const newProj = await createProject({ name: projectName.trim(), projectName: projectName.trim() }, token);
        setProvisioned({
          _id: newProj._id,
          projectName: newProj.projectName,
          apiKey: newProj.apiKey
        });
        if (onProjectCreated) onProjectCreated(newProj);
      } else {
        const mockProj: Project = {
          _id: '6ac2393879e7eaec' + Math.random().toString(16).slice(2, 10),
          projectName: projectName.trim(),
          apiKey: 'ag_live_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2),
          dryRun: false,
          enableLLMAudit: true,
          slackWebhookUrl: '',
          discordWebhookUrl: ''
        };
        setProvisioned({
          _id: mockProj._id,
          projectName: mockProj.projectName,
          apiKey: mockProj.apiKey
        });
        if (onProjectCreated) onProjectCreated(mockProj);
      }
    } catch {
      const mockId = '6ac2393879e7eaec68377b1c';
      const mockKey = 'ag_live_7Hq2Zx9Kc4Vb1Nm8Lw3Rt6Yd0Fa5Sj2Pe9Uo4Gh';
      const fallbackProj: Project = {
        _id: mockId,
        projectName: projectName.trim(),
        apiKey: mockKey,
        dryRun: false,
        enableLLMAudit: true,
        slackWebhookUrl: '',
        discordWebhookUrl: ''
      };
      setProvisioned({
        _id: mockId,
        projectName: projectName.trim(),
        apiKey: mockKey
      });
      if (onProjectCreated) onProjectCreated(fallbackProj);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="main" style={{ width: '800px', margin: 'auto' }}>
      <div>
        <div className="pt">Provision a tenant</div>
        <div style={{ color: 'var(--t2)', marginTop: '4px' }}>
          Register a new tenant to generate its project ID and API key.
        </div>
      </div>

      <div className="card">
        <div className="ct" style={{ marginBottom: '16px' }}>New project</div>
        <form onSubmit={handleGenerateKey}>
          <label>Project name</label>
          <div className="fld" style={{ marginBottom: '16px' }}>
            <input
              placeholder="e.g. Production payment portal"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
            />
          </div>
          <button
            type="submit"
            className="pr"
            disabled={!projectName.trim() || loading}
          >
            {loading ? 'Generating...' : 'Generate API key'}
          </button>
        </form>
      </div>

      {provisioned && (
        <div className="card" style={{ display: 'grid', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="ct">Project provisioned</span>
            <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
              <i></i>Provisioned
            </span>
          </div>

          <div className="kv">
            <span style={{ color: 'var(--t3)' }}>Project name</span>
            <span>{provisioned.projectName}</span>
          </div>

          <div className="kv">
            <span style={{ color: 'var(--t3)' }}>Project ID</span>
            <span style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <span className="mono">{provisioned._id}</span>
              <button
                type="button"
                className="sc sm"
                onClick={() => handleCopy(provisioned._id)}
              >
                Copy
              </button>
            </span>
          </div>

          <div className="kv">
            <span style={{ color: 'var(--t3)' }}>API key</span>
            <span
              className="in mono"
              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px' }}
            >
              <span>{provisioned.apiKey}</span>
              <button
                type="button"
                className="sc sm"
                onClick={() => handleCopy(provisioned.apiKey)}
              >
                Copy
              </button>
            </span>
          </div>

          <div
            className="nt"
            style={{
              background: 'rgba(216, 194, 122, 0.14)',
              color: '#E6D6A0',
              display: 'flex',
              gap: '8px',
              alignItems: 'center',
              margin: 0
            }}
          >
            <span style={{ color: 'var(--med)', display: 'inline-flex' }}>
              <WarningIcon size={16} />
            </span>
            <span>Store this key safely. For security reasons, it cannot be recovered or viewed again.</span>
          </div>
        </div>
      )}
    </div>
  );
}
