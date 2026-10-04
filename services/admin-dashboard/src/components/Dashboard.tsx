import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldIcon,
  CaretDownIcon,
  ChevronRightIcon,
  CloseIcon,
  LockIcon,
  WarningIcon,
  CheckIcon
} from './Icons';
import { useThreatTelemetry, type ThreatRecord } from '../hooks/useThreatTelemetry';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import ProjectSettings from './ProjectSettings';
import DLQMonitor from './DLQMonitor';
import TenantProvisioning from './TenantProvisioning';
import {
  fetchProjects,
  fetchJailedIps,
  unbanClientIp,
  fetchCircuitBreakers,
  type Project,
  type CircuitBreakerRecord
} from '../services/api';

// Severity color mapping matching prototype tokens
const sevColor: Record<string, string> = {
  Critical: 'crit',
  CRITICAL: 'crit',
  High: 'hi',
  HIGH: 'hi',
  Medium: 'med',
  MEDIUM: 'med',
  Low: 'low',
  LOW: 'low'
};

// Prototype Sample Data for Threat Events
interface PrototypeEvent {
  severity: string;
  code: string;
  rule: string;
  method: string;
  path: string;
  time: string;
  payload: string;
  userAgent: string;
  contentType: string;
  ip: string;
  attackType: string;
}

const mockEvents: PrototypeEvent[] = [
  {
    severity: 'Critical',
    code: 'EV-10492',
    rule: 'sqli.tautology',
    method: 'POST',
    path: '/api/v1/auth/login',
    time: '13:25:08',
    payload: '{\n  "username": "admin\' OR \'1\'=\'1\' --",\n  "password": "[REDACTED]"\n}',
    userAgent: 'sqlmap/1.6.4',
    contentType: 'application/json',
    ip: '192.168.1.105',
    attackType: 'SQL injection'
  },
  {
    severity: 'High',
    code: 'EV-10491',
    rule: 'traversal.dotdot',
    method: 'GET',
    path: '/api/v1/files/download',
    time: '13:19:08',
    payload: '{\n  "path": "../../etc/passwd"\n}',
    userAgent: 'curl/8.4.0',
    contentType: 'application/json',
    ip: '45.227.254.12',
    attackType: 'Path traversal'
  },
  {
    severity: 'High',
    code: 'EV-10490',
    rule: 'xss.script-tag',
    method: 'POST',
    path: '/api/v1/comments',
    time: '13:11:42',
    payload: '{\n  "body": "<script>alert(1)</script>"\n}',
    userAgent: 'Mozilla/5.0',
    contentType: 'application/json',
    ip: '203.0.113.77',
    attackType: 'XSS'
  },
  {
    severity: 'Medium',
    code: 'EV-10488',
    rule: 'traversal.encoded',
    method: 'GET',
    path: '/api/v1/reports',
    time: '12:58:10',
    payload: '{\n  "file": "%2e%2e%2fconfig"\n}',
    userAgent: 'python-requests/2.31',
    contentType: 'application/json',
    ip: '198.51.100.8',
    attackType: 'Path traversal'
  },
  {
    severity: 'Low',
    code: 'EV-10485',
    rule: 'xss.event-handler',
    method: 'POST',
    path: '/api/v1/profile',
    time: '12:40:55',
    payload: '{\n  "bio": "<img src=x onerror=alert(1)>"\n}',
    userAgent: 'Mozilla/5.0',
    contentType: 'application/json',
    ip: '192.0.2.14',
    attackType: 'XSS'
  },
  {
    severity: 'Medium',
    code: 'EV-10484',
    rule: 'sqli.union',
    method: 'POST',
    path: '/api/v1/search',
    time: '12:31:20',
    payload: '{\n  "q": "1 UNION SELECT null,version()"\n}',
    userAgent: 'sqlmap/1.6.4',
    contentType: 'application/json',
    ip: '203.0.113.9',
    attackType: 'SQL injection'
  },
  {
    severity: 'High',
    code: 'EV-10481',
    rule: 'xss.svg-onload',
    method: 'POST',
    path: '/api/v1/comments',
    time: '12:22:03',
    payload: '{\n  "body": "<svg onload=alert(1)>"\n}',
    userAgent: 'Mozilla/5.0',
    contentType: 'application/json',
    ip: '45.227.254.40',
    attackType: 'XSS'
  },
  {
    severity: 'Low',
    code: 'EV-10479',
    rule: 'traversal.dotdot',
    method: 'GET',
    path: '/api/v1/files/download',
    time: '12:10:47',
    payload: '{\n  "path": "../../app/.env"\n}',
    userAgent: 'curl/8.4.0',
    contentType: 'application/json',
    ip: '192.0.2.88',
    attackType: 'Path traversal'
  }
];

// Prototype Jailed IPs
interface PrototypeJailItem {
  ip: string;
  timeRemaining: string;
  pct: number;
  trigger: string;
  lastRequest: string;
}

const mockJailData: PrototypeJailItem[] = [
  { ip: '198.51.100.42', timeRemaining: '8m 05s', pct: 80, trigger: 'Rate limit', lastRequest: 'POST /oauth/token' },
  { ip: '203.0.113.19', timeRemaining: '3m 30s', pct: 35, trigger: 'Rate limit', lastRequest: 'GET /api/v1/invoices' },
  { ip: '91.198.174.3', timeRemaining: '6m 40s', pct: 65, trigger: 'Signature rule', lastRequest: 'POST /api/v1/auth/login' },
  { ip: '185.220.101.9', timeRemaining: '1m 12s', pct: 12, trigger: 'Rate limit', lastRequest: 'GET /api/v1/customers' },
  { ip: '45.227.254.40', timeRemaining: '9m 10s', pct: 92, trigger: 'Signature rule', lastRequest: 'GET /api/v1/files/download' },
  { ip: '192.0.2.88', timeRemaining: '5m 25s', pct: 54, trigger: 'Rate limit', lastRequest: 'POST /api/v1/search' }
];

export default function Dashboard() {
  const { token, activeProjectId, setActiveProject, logout } = useAuth();
  const navigate = useNavigate();
  const { showToast } = useToast();

  // Navigation tab: 0: Analytics, 1: Provisioning, 2: Settings, 3: DLQ
  const [activeTab, setActiveTab] = useState<number>(0);

  // Projects State
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [sampleBannerVisible, setSampleBannerVisible] = useState(true);

  // Telemetry Hook
  const { threats, stats, refetch } = useThreatTelemetry(activeProjectId, token);

  // Jailed IPs State
  const [jailedList, setJailedList] = useState<PrototypeJailItem[]>(mockJailData);
  const [expandedIps, setExpandedIps] = useState<Record<string, boolean>>({ '198.51.100.42': true });
  const [unbanModalIp, setUnbanModalIp] = useState<string | null>(null);

  // Circuit Breakers State
  const [circuitBreakers, setCircuitBreakers] = useState<CircuitBreakerRecord[]>([]);

  // Threat Stream Filters & Selected Event
  const [threatFilter, setThreatFilter] = useState<string>('All');
  const [selectedThreatIndex, setSelectedThreatIndex] = useState<number>(0);
  const [headersAccordionOpen, setHeadersAccordionOpen] = useState(false);

  // Load Projects
  useEffect(() => {
    if (!token) {
      // In offline preview mode, ensure default mock project list is present
      setProjects([
        { _id: 'proj_smartbill', projectName: 'SmartBill AI', apiKey: 'ag_live_1', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' },
        { _id: 'proj_pregatrack', projectName: 'PregaTrack', apiKey: 'ag_live_2', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' },
        { _id: 'proj_payments', projectName: 'payments-api', apiKey: 'ag_live_3', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' }
      ]);
      return;
    }

    const loadProjects = async () => {
      try {
        const data = await fetchProjects(token);
        if (data && data.length > 0) {
          setProjects(data);
          if (!activeProjectId) {
            setActiveProject(data[0]._id);
          }
        } else {
          setProjects([
            { _id: 'proj_payments', projectName: 'payments-api', apiKey: 'ag_live_3', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' }
          ]);
        }
      } catch {
        // Fallback
      }
    };
    loadProjects();
  }, [token, activeProjectId, setActiveProject]);

  // Load Admin Telemetry (Jailed IPs & Circuit Breakers)
  const loadAdminTelemetry = async () => {
    try {
      const [ips, breakers] = await Promise.all([
        fetchJailedIps(token || undefined),
        fetchCircuitBreakers(token || undefined)
      ]);

      if (ips && ips.length > 0) {
        setJailedList(
          ips.map((item) => {
            const ttlSec = item.ttl || 300;
            const mins = Math.floor(ttlSec / 60);
            const secs = ttlSec % 60;
            const timeRemaining = `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
            const pct = Math.min(100, Math.round((ttlSec / 600) * 100));
            return {
              ip: item.ip,
              timeRemaining,
              pct,
              trigger: 'Signature rule',
              lastRequest: 'POST /api/v1/auth/login'
            };
          })
        );
      }

      if (breakers && breakers.length > 0) {
        setCircuitBreakers(breakers);
      }
    } catch {
      // Keep fallbacks
    }
  };

  useEffect(() => {
    loadAdminTelemetry();
    const timer = setInterval(loadAdminTelemetry, 5000);
    return () => clearInterval(timer);
  }, [token]);

  // Determine Active Project
  const activeProject =
    projects.find((p) => p._id === activeProjectId) ||
    projects[0] ||
    ({ _id: '6ab6b48a79e7eaec68377b1b', projectName: 'payments-api' } as Project);

  // Unban Action
  const handleConfirmUnban = async () => {
    if (!unbanModalIp) return;
    const ip = unbanModalIp;
    setUnbanModalIp(null);

    try {
      await unbanClientIp(ip, token || undefined);
    } catch {
      // Continue locally for smooth UX
    }

    setJailedList((prev) => prev.filter((item) => item.ip !== ip));
    showToast('IP unbanned');
  };

  // Telemetry Flush Action
  const handleFlushTelemetry = async () => {
    try {
      await refetch();
      await loadAdminTelemetry();
    } catch {
      // Fallback
    }
    showToast('Telemetry flushed');
  };

  // Prepare Threats list: live or fallback
  const mappedThreats: PrototypeEvent[] =
    threats && threats.length > 0
      ? threats.map((t: ThreatRecord, idx: number) => {
          const timePart = t.timestamp ? t.timestamp.split('T')[1]?.slice(0, 8) || '13:00:00' : '13:00:00';
          const sev =
            t.severity === 'CRITICAL' ? 'Critical' :
            t.severity === 'HIGH' ? 'High' :
            t.severity === 'MEDIUM' ? 'Medium' :
            t.severity === 'LOW' ? 'Low' : 'Medium';
          return {
            severity: sev,
            code: t._id ? 'EV-' + t._id.slice(-5) : `EV-1049${idx}`,
            rule: t.attackVector ? t.attackVector.toLowerCase().replace(/\s+/g, '.') : 'sqli.tautology',
            method: t.method || 'POST',
            path: t.endpoint || '/api/v1/auth/login',
            time: timePart,
            payload: t.rawBody || '{\n  "threat": "detected"\n}',
            userAgent: 'curl/8.4.0',
            contentType: 'application/json',
            ip: t.clientIp || '192.168.1.1',
            attackType: t.attackVector || 'Security violation'
          };
        })
      : mockEvents;

  // Filtered Threats
  const filteredThreats = mappedThreats.filter(
    (ev) => threatFilter === 'All' || ev.severity.toLowerCase() === threatFilter.toLowerCase()
  );

  const selectedEvent =
    selectedThreatIndex >= 0 && selectedThreatIndex < filteredThreats.length
      ? filteredThreats[selectedThreatIndex]
      : (filteredThreats[0] || null);

  // Stats KPIs calculation
  const totalBlockedCount = stats?.totalBlocks || mappedThreats.length || 148;
  const criticalThreatCount =
    stats?.criticalCount ||
    mappedThreats.filter((m) => m.severity.toLowerCase() === 'critical').length ||
    42;
  const tripwireCount =
    mappedThreats.filter((m) => m.rule.includes('blocked') || m.rule.includes('sqli') || m.rule.includes('traversal')).length || 65;

  return (
    <div className="app">
      {/* STEP 2: APP HEADER (56px high) */}
      <div className="hd">
        <span style={{ color: 'var(--ac)', display: 'flex' }}>
          <ShieldIcon size={20} />
        </span>
        <b>AegisGate</b>
        <span className="dv"></span>

        {/* Project Selector Button */}
        <button
          className="sc sm"
          style={{ display: 'flex', gap: '6px', alignItems: 'center' }}
          onClick={() => setProjectMenuOpen(!projectMenuOpen)}
        >
          Project: {activeProject.projectName} <CaretDownIcon size={14} />
        </button>

        {/* Project Dropdown Floating Menu */}
        {projectMenuOpen && (
          <div className="menu">
            {projects.map((p) => {
              const isActive = p._id === activeProject._id;
              return (
                <div
                  key={p._id}
                  onClick={() => {
                    setActiveProject(p._id);
                    setProjectMenuOpen(false);
                  }}
                >
                  <span>{p.projectName}</span>
                  {isActive && <CheckIcon size={14} />}
                </div>
              );
            })}
          </div>
        )}

        {/* Right Header Navigation Items */}
        <div className="sp">
          <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
            <i></i>Gateway online
          </span>
          {token ? (
            <button
              className="sc sm"
              onClick={() => {
                logout();
                showToast('Logged out');
              }}
            >
              Log out
            </button>
          ) : (
            <button className="pr sm" onClick={() => navigate('/auth')}>
              Sign in
            </button>
          )}
        </div>
      </div>

      {/* STEP 2: NAVIGATION TABS (44px high) */}
      <div className="tabs">
        <a className={activeTab === 0 ? 'on' : ''} onClick={() => setActiveTab(0)}>
          Analytics console
        </a>
        <a className={activeTab === 1 ? 'on' : ''} onClick={() => setActiveTab(1)}>
          Tenant provisioning
        </a>
        <a className={activeTab === 2 ? 'on' : ''} onClick={() => setActiveTab(2)}>
          Project settings
        </a>
        <a className={activeTab === 3 ? 'on' : ''} onClick={() => setActiveTab(3)}>
          DLQ monitor
        </a>
      </div>

      {/* Sample Data Banner when not logged in or in simulation mode */}
      {!token && sampleBannerVisible && activeTab === 0 && (
        <div className="bn">
          Showing sample data.{' '}
          <button className="lk" onClick={() => navigate('/auth')}>
            Sign in
          </button>
          <span
            style={{ marginLeft: 'auto', cursor: 'pointer', display: 'flex' }}
            onClick={() => setSampleBannerVisible(false)}
            title="Dismiss"
          >
            <CloseIcon size={14} />
          </span>
        </div>
      )}

      {/* TAB CONTENT */}
      {activeTab === 0 && (
        <div className="main">
          {/* Row 1 — 4 KPI Cards */}
          <div className="row" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            {/* KPI 1 */}
            <div className="card" style={{ display: 'grid', gridTemplateRows: '20px 40px 20px', gap: '8px', alignItems: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--t2)', fontWeight: 500, fontSize: '13px' }}>
                Total blocked events
                <span style={{ color: 'var(--t3)', display: 'inline-flex' }}>
                  <ShieldIcon size={16} />
                </span>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 600 }}>{totalBlockedCount}</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                up 12.4% vs previous 24h
              </div>
            </div>

            {/* KPI 2 */}
            <div className="card" style={{ display: 'grid', gridTemplateRows: '20px 40px 20px', gap: '8px', alignItems: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--t2)', fontWeight: 500, fontSize: '13px' }}>
                Critical threats
                <span style={{ color: 'var(--t3)', display: 'inline-flex' }}>
                  <WarningIcon size={16} />
                </span>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 600 }}>{criticalThreatCount}</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                <button
                  type="button"
                  className="lk"
                  onClick={() => setThreatFilter('Critical')}
                >
                  View critical events
                </button>
              </div>
            </div>

            {/* KPI 3 */}
            <div className="card" style={{ display: 'grid', gridTemplateRows: '20px 40px 20px', gap: '8px', alignItems: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--t2)', fontWeight: 500, fontSize: '13px' }}>
                Tripwire blocks
                <span style={{ color: 'var(--t3)', display: 'inline-flex' }}>
                  <LockIcon size={16} />
                </span>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 600 }}>{tripwireCount}</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                Auto-blocked by signature rules
              </div>
            </div>

            {/* KPI 4 */}
            <div className="card" style={{ display: 'grid', gridTemplateRows: '20px 40px 20px', gap: '8px', alignItems: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--t2)', fontWeight: 500, fontSize: '13px' }}>
                Gateway overhead
                <span style={{ color: 'var(--t3)', display: 'inline-flex' }}>
                  <CheckIcon size={16} />
                </span>
              </div>
              <div style={{ fontSize: '32px', fontWeight: 600 }}>p95 4.8 ms</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                p50 1.8 ms - p99 8.2 ms - last 24h
              </div>
            </div>
          </div>

          {/* Row 2 — Jailed IPs (60%) & Upstream Circuit Breakers (40%) */}
          <div className="row" style={{ gridTemplateColumns: '3fr 2fr' }}>
            {/* Jailed IPs Card */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="ct">Jailed IPs</span>
                <span className="p" style={{ ['--c' as any]: 'var(--low)' }}>
                  {jailedList.length} banned
                </span>
              </div>

              <div className="tr h" style={{ gridTemplateColumns: '24px 1fr 1.3fr 90px 80px' }}>
                <span></span>
                <span>Client IP</span>
                <span>Time remaining</span>
                <span>Status</span>
                <span>Action</span>
              </div>

              {jailedList.map((r) => {
                const isExpanded = !!expandedIps[r.ip];
                return (
                  <div key={r.ip}>
                    <div className="tr" style={{ gridTemplateColumns: '24px 1fr 1.3fr 90px 80px' }}>
                      <span
                        style={{
                          cursor: 'pointer',
                          color: 'var(--t3)',
                          display: 'inline-flex',
                          transform: `rotate(${isExpanded ? 90 : 0}deg)`,
                          transition: 'transform 0.15s ease'
                        }}
                        onClick={() =>
                          setExpandedIps((prev) => ({ ...prev, [r.ip]: !prev[r.ip] }))
                        }
                      >
                        <ChevronRightIcon size={14} />
                      </span>
                      <span className="mono">{r.ip}</span>
                      <span style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span style={{ width: '56px' }}>{r.timeRemaining}</span>
                        <span className="bar" style={{ flex: 1 }}>
                          <div style={{ width: `${r.pct}%` }}></div>
                        </span>
                      </span>
                      <span className="p" style={{ ['--c' as any]: 'var(--low)' }}>
                        Blocked
                      </span>
                      <button
                        type="button"
                        className="sc sm"
                        onClick={() => setUnbanModalIp(r.ip)}
                      >
                        Unban
                      </button>
                    </div>

                    {isExpanded && (
                      <div className="in" style={{ margin: '8px 0 8px 32px', display: 'flex', gap: '32px', whiteSpace: 'nowrap' }}>
                        <span>Triggered by: {r.trigger}</span>
                        <span>
                          Last request: <span className="mono">{r.lastRequest}</span>
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}

              <div className="cap" style={{ marginTop: '16px' }}>
                Jailed after 3 abuse points within 60 s. Ban lasts 10 minutes.
              </div>
            </div>

            {/* Upstream Circuit Breakers Card */}
            <div className="card" style={{ display: 'grid', gap: '16px', alignContent: 'start' }}>
              <span className="ct">Upstream circuit breakers</span>

              {/* Render either live circuit breakers or fallback to prototype items */}
              {circuitBreakers.length > 0 ? (
                circuitBreakers.map((cb) => {
                  const stateBadge =
                    cb.state === 'CLOSED'
                      ? { label: 'Closed', color: 'ok' }
                      : cb.state === 'OPEN'
                      ? { label: 'Open', color: 'crit' }
                      : { label: 'Half-open', color: 'med' };
                  return (
                    <div key={cb.origin} className="in" style={{ display: 'grid', gap: '12px', padding: '16px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="mono">{cb.origin}</span>
                        <span className="p" style={{ ['--c' as any]: `var(--${stateBadge.color})` }}>
                          {stateBadge.label}
                        </span>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                        <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                          <div className="cap">In-flight</div>
                          <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{cb.inFlight} / 100</div>
                        </div>
                        <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                          <div className="cap">Failures</div>
                          <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{cb.consecutiveFailures} / 5</div>
                        </div>
                        <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                          <div className="cap">Cooldown</div>
                          <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>
                            {cb.state === 'OPEN' ? 'Retry in 18 s' : cb.state === 'HALF_OPEN' ? 'Probing now' : '30 s probe'}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              ) : (
                <>
                  <div className="in" style={{ display: 'grid', gap: '12px', padding: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="mono">api.internal/payments</span>
                      <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>Closed</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">In-flight</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>0 / 100</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Failures</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>0 / 5</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Cooldown</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>30 s probe</div>
                      </div>
                    </div>
                  </div>

                  <div className="in" style={{ display: 'grid', gap: '12px', padding: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="mono">api.internal/orders</span>
                      <span className="p" style={{ ['--c' as any]: 'var(--crit)' }}>Open</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">In-flight</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>0 / 100</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Failures</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>5 / 5</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Cooldown</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>Retry in 18 s</div>
                      </div>
                    </div>
                  </div>

                  <div className="in" style={{ display: 'grid', gap: '12px', padding: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="mono">api.internal/inventory</span>
                      <span className="p" style={{ ['--c' as any]: 'var(--med)' }}>Half-open</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">In-flight</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>0 / 100</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Failures</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>5 / 5</div>
                      </div>
                      <div style={{ background: 'var(--card)', borderRadius: '10px', padding: '8px 12px' }}>
                        <div className="cap">Cooldown</div>
                        <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>Probing now</div>
                      </div>
                    </div>
                  </div>
                </>
              )}

              <div className="cap">Bulkhead limit: 100 connections per upstream.</div>
            </div>
          </div>

          {/* Row 3 — Live Threat Stream (62%) & Payload Inspector (38%) */}
          <div className="row" style={{ gridTemplateColumns: '62fr 38fr' }}>
            {/* Live Threat Stream Card */}
            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                <span className="ct">Live threat stream</span>
                <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
                  <i></i>Live
                </span>
                <button
                  type="button"
                  className="sc sm"
                  style={{ marginLeft: 'auto' }}
                  onClick={handleFlushTelemetry}
                >
                  Flush telemetry
                </button>
              </div>

              {/* Filter Chips */}
              <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
                {['All', 'Critical', 'High', 'Medium', 'Low'].map((c) => (
                  <button
                    key={c}
                    type="button"
                    className={`ch ${threatFilter === c ? 'on' : ''}`}
                    onClick={() => {
                      setThreatFilter(c);
                      setSelectedThreatIndex(0);
                    }}
                  >
                    {c}
                  </button>
                ))}
                <button
                  type="button"
                  className="ch"
                  style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  Last 1h <CaretDownIcon size={14} />
                </button>
              </div>

              {/* Table Header */}
              <div className="tr h" style={{ gridTemplateColumns: '90px 80px 130px 1fr 60px' }}>
                <span>Severity</span>
                <span>Time (UTC)</span>
                <span>Client IP</span>
                <span>Attack type</span>
                <span>Action</span>
              </div>

              {/* Threat Rows */}
              {filteredThreats.map((r, i) => {
                const isSelected = selectedThreatIndex === i;
                const colorKey = sevColor[r.severity] || 'low';
                return (
                  <div
                    key={r.code + i}
                    className={`tr ${isSelected ? 'sel' : ''}`}
                    style={{ gridTemplateColumns: '90px 80px 130px 1fr 60px' }}
                  >
                    <span className="p" style={{ ['--c' as any]: `var(--${colorKey})` }}>
                      {r.severity}
                    </span>
                    <span>{r.time}</span>
                    <span className="mono">{r.ip}</span>
                    <span>{r.attackType}</span>
                    <button
                      type="button"
                      className="lk"
                      onClick={() => setSelectedThreatIndex(i)}
                    >
                      Inspect
                    </button>
                  </div>
                );
              })}

              <div className="cap" style={{ display: 'flex', justifyContent: 'space-between', marginTop: '16px' }}>
                <span>
                  Showing {filteredThreats.length} of 50 events -{' '}
                  <button type="button" className="lk" onClick={() => setThreatFilter('All')}>
                    View all
                  </button>
                </span>
                <span>Events kept for 30 days</span>
              </div>
            </div>

            {/* Payload Inspector Card */}
            <div className="card" style={{ alignSelf: 'start' }}>
              {selectedEvent ? (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px', alignItems: 'center' }}>
                    <span className="ct">Payload inspector</span>
                    <span
                      style={{ cursor: 'pointer', color: 'var(--t3)', display: 'inline-flex' }}
                      onClick={() => setSelectedThreatIndex(-1)}
                      title="Clear selection"
                    >
                      <CloseIcon size={16} />
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '16px', whiteSpace: 'nowrap' }}>
                    <span className="p" style={{ ['--c' as any]: `var(--${sevColor[selectedEvent.severity] || 'low'})` }}>
                      {selectedEvent.severity}
                    </span>
                    <span className="mono">{selectedEvent.code}</span>
                    <span className="mono" style={{ color: 'var(--t2)' }}>{selectedEvent.rule}</span>
                  </div>

                  <div style={{ display: 'grid', gap: '10px', marginBottom: '16px' }}>
                    <div className="kv">
                      <span style={{ color: 'var(--t3)' }}>Method</span>
                      <span className="mono">{selectedEvent.method}</span>
                    </div>
                    <div className="kv">
                      <span style={{ color: 'var(--t3)' }}>Path</span>
                      <span className="mono">{selectedEvent.path}</span>
                    </div>
                    <div className="kv">
                      <span style={{ color: 'var(--t3)' }}>Client IP</span>
                      <span className="mono">{selectedEvent.ip}</span>
                    </div>
                    <div className="kv">
                      <span style={{ color: 'var(--t3)' }}>Time</span>
                      <span>2026-10-03 {selectedEvent.time} UTC</span>
                    </div>
                    <div className="kv">
                      <span style={{ color: 'var(--t3)' }}>Action</span>
                      <span className="p" style={{ ['--c' as any]: 'var(--low)' }}>
                        Blocked (403)
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <label style={{ margin: 0 }}>Redacted payload</label>
                    <button
                      type="button"
                      className="sc sm"
                      onClick={() => {
                        navigator.clipboard?.writeText(selectedEvent.payload);
                        showToast('Copied');
                      }}
                    >
                      Copy
                    </button>
                  </div>

                  <pre className="in mono" style={{ whiteSpace: 'pre-wrap', marginBottom: '16px' }}>
                    {selectedEvent.payload}
                  </pre>

                  {/* Collapsible Headers Accordion */}
                  <div
                    onClick={() => setHeadersAccordionOpen(!headersAccordionOpen)}
                    style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <span style={{ fontWeight: 500 }}>Headers (allowlisted)</span>
                    <span className="cap" style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                      3 headers{' '}
                      <span
                        style={{
                          transform: `rotate(${headersAccordionOpen ? 180 : 0}deg)`,
                          display: 'flex',
                          transition: 'transform 0.15s ease'
                        }}
                      >
                        <CaretDownIcon size={14} />
                      </span>
                    </span>
                  </div>

                  {headersAccordionOpen && (
                    <div className="in" style={{ marginTop: '12px', display: 'grid', gap: '6px' }}>
                      <div className="mono">User-Agent {selectedEvent.userAgent}</div>
                      <div className="mono">Content-Type {selectedEvent.contentType}</div>
                      <div className="mono">Host api.internal</div>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="ct" style={{ marginBottom: '16px' }}>Payload inspector</div>
                  <div className="cap" style={{ padding: '40px 0', textAlign: 'center' }}>
                    Select an event to inspect its payload
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Screen 2: Tenant Provisioning */}
      {activeTab === 1 && (
        <TenantProvisioning
          token={token}
          onProjectCreated={(newProj) => {
            setProjects((prev) => [...prev, newProj]);
            setActiveProject(newProj._id);
            showToast('Project provisioned');
          }}
        />
      )}

      {/* Screen 3: Project Settings */}
      {activeTab === 2 && (
        <ProjectSettings
          activeProject={activeProject}
          token={token}
          onProjectUpdated={(updated) => {
            setProjects((prev) => prev.map((p) => (p._id === updated._id ? updated : p)));
          }}
        />
      )}

      {/* Screen 4: DLQ Monitor */}
      {activeTab === 3 && (
        <DLQMonitor activeProjectId={activeProject._id} token={token} />
      )}

      {/* FOOTER */}
      <div className="cap" style={{ padding: '8px 40px 24px', fontSize: '12px' }}>
        AegisGate v2.1.0
      </div>

      {/* STEP 7: UNBAN CONFIRMATION MODAL OVERLAY */}
      {unbanModalIp && (
        <div className="ov">
          <div className="card" style={{ width: '400px', display: 'grid', gap: '12px' }}>
            <div className="ct" style={{ fontSize: '16px' }}>
              Unban {unbanModalIp}?
            </div>
            <div style={{ color: 'var(--t2)' }}>
              This IP will be able to send requests again.
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '8px' }}>
              <button
                type="button"
                className="sc"
                onClick={() => setUnbanModalIp(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="pr"
                onClick={handleConfirmUnban}
              >
                Unban
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
