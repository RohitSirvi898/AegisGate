import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GateIcon,
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
  unbanClientIp,
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

interface PrototypeEvent {
  severity: string;
  code: string;
  rule: string;
  method: string;
  path: string;
  time: string;
  timestamp: string;
  payload: string;
  userAgent: string;
  contentType: string;
  ip: string;
  attackType: string;
}

interface PrototypeJailItem {
  ip: string;
  timeRemaining: string;
  pct: number;
  trigger: string;
  lastRequest: string;
}

type TimeWindow = '15m' | '1h' | '24h' | '7d';

interface TimeWindowOption {
  id: TimeWindow;
  label: string;
  durationMs: number;
}

const TIME_WINDOWS: TimeWindowOption[] = [
  { id: '15m', label: 'Last 15m', durationMs: 15 * 60 * 1000 },
  { id: '1h', label: 'Last 1h', durationMs: 60 * 60 * 1000 },
  { id: '24h', label: 'Last 24h', durationMs: 24 * 60 * 60 * 1000 },
  { id: '7d', label: 'Last 7d', durationMs: 7 * 24 * 60 * 60 * 1000 }
];

// ==========================================
// MOCK DATA FIXTURES (For Unauthenticated Preview Only)
// ==========================================
const MOCK_METRICS = {
  totalBlocks: 148,
  criticalCount: 42,
  tripwireCount: 65,
  overhead: 'p95 4.8 ms'
};

const MOCK_PROJECTS: Project[] = [
  { _id: 'proj_smartbill', projectName: 'SmartBill AI', apiKey: 'ag_live_1', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' },
  { _id: 'proj_pregatrack', projectName: 'PregaTrack', apiKey: 'ag_live_2', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' },
  { _id: 'proj_payments', projectName: 'payments-api', apiKey: 'ag_live_3', dryRun: false, enableLLMAudit: true, slackWebhookUrl: '', discordWebhookUrl: '' }
];

const MOCK_CIRCUIT_BREAKERS: CircuitBreakerRecord[] = [
  { origin: 'api.internal/payments', state: 'CLOSED', inFlight: 0, consecutiveFailures: 0, lastStateChange: Date.now() },
  { origin: 'api.internal/orders', state: 'OPEN', inFlight: 0, consecutiveFailures: 5, lastStateChange: Date.now() },
  { origin: 'api.internal/inventory', state: 'HALF_OPEN', inFlight: 0, consecutiveFailures: 5, lastStateChange: Date.now() }
];

const MOCK_JAILED_IPS: PrototypeJailItem[] = [
  { ip: '198.51.100.42', timeRemaining: '8m 05s', pct: 80, trigger: 'Rate limit', lastRequest: 'POST /oauth/token' },
  { ip: '203.0.113.19', timeRemaining: '3m 30s', pct: 35, trigger: 'Rate limit', lastRequest: 'GET /api/v1/invoices' },
  { ip: '91.198.174.3', timeRemaining: '6m 40s', pct: 65, trigger: 'Signature rule', lastRequest: 'POST /api/v1/auth/login' },
  { ip: '185.220.101.9', timeRemaining: '1m 12s', pct: 12, trigger: 'Rate limit', lastRequest: 'GET /api/v1/customers' },
  { ip: '45.227.254.40', timeRemaining: '9m 10s', pct: 92, trigger: 'Signature rule', lastRequest: 'GET /api/v1/files/download' },
  { ip: '192.0.2.88', timeRemaining: '5m 25s', pct: 54, trigger: 'Rate limit', lastRequest: 'POST /api/v1/search' }
];

// Helper to format mock timestamps relative to now
const nowMs = Date.now();
const formatIso = (offsetMs: number) => new Date(nowMs - offsetMs).toISOString();
const formatTimeOnly = (offsetMs: number) => new Date(nowMs - offsetMs).toTimeString().split(' ')[0] || '12:00:00';

const MOCK_THREATS: PrototypeEvent[] = [
  {
    severity: 'Critical',
    code: 'EV-10492',
    rule: 'sqli.tautology',
    method: 'POST',
    path: '/api/v1/auth/login',
    time: formatTimeOnly(8 * 60 * 1000),
    timestamp: formatIso(8 * 60 * 1000), // 8 mins ago
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
    time: formatTimeOnly(12 * 60 * 1000),
    timestamp: formatIso(12 * 60 * 1000), // 12 mins ago
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
    time: formatTimeOnly(25 * 60 * 1000),
    timestamp: formatIso(25 * 60 * 1000), // 25 mins ago
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
    time: formatTimeOnly(45 * 60 * 1000),
    timestamp: formatIso(45 * 60 * 1000), // 45 mins ago
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
    time: formatTimeOnly(2 * 60 * 60 * 1000),
    timestamp: formatIso(2 * 60 * 60 * 1000), // 2 hours ago
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
    time: formatTimeOnly(4 * 60 * 60 * 1000),
    timestamp: formatIso(4 * 60 * 60 * 1000), // 4 hours ago
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
    time: formatTimeOnly(18 * 60 * 60 * 1000),
    timestamp: formatIso(18 * 60 * 60 * 1000), // 18 hours ago
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
    time: formatTimeOnly(48 * 60 * 60 * 1000),
    timestamp: formatIso(48 * 60 * 60 * 1000), // 2 days ago
    payload: '{\n  "path": "../../app/.env"\n}',
    userAgent: 'curl/8.4.0',
    contentType: 'application/json',
    ip: '192.0.2.88',
    attackType: 'Path traversal'
  }
];

const mapThreatRecordToPrototypeEvent = (t: ThreatRecord, idx: number): PrototypeEvent => {
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
    timestamp: t.timestamp || new Date().toISOString(),
    payload: t.rawBody || '{\n  "threat": "detected"\n}',
    userAgent: 'curl/8.4.0',
    contentType: 'application/json',
    ip: t.clientIp || '192.168.1.1',
    attackType: t.attackVector || 'Security violation'
  };
};

export default function Dashboard() {
  const { token, activeProjectId, setActiveProject, logout, isLoading } = useAuth();
  const navigate = useNavigate();
  const { showToast } = useToast();

  // Navigation tab: 0: Analytics, 1: Provisioning, 2: Settings, 3: DLQ
  const [activeTab, setActiveTab] = useState<number>(0);

  // Projects State - Synchronously hydrated from localStorage if available
  const [projects, setProjects] = useState<Project[]>(() => {
    if (!token) return MOCK_PROJECTS;
    try {
      const saved = localStorage.getItem('aegis_projects');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [sampleBannerVisible, setSampleBannerVisible] = useState(true);
  const projectMenuRef = useRef<HTMLDivElement>(null);

  // Consolidated Telemetry, Circuit Breakers & Jailed IPs Hook
  const {
    threats,
    stats,
    circuitBreakers,
    jailedList,
    setJailedList,
    connectionStatus,
    refetch
  } = useThreatTelemetry(activeProjectId, token);

  // Jailed IPs UI State
  const [expandedIps, setExpandedIps] = useState<Record<string, boolean>>({});
  const [unbanModalIp, setUnbanModalIp] = useState<string | null>(null);

  // Threat Stream Filters & Selected Event
  const [threatFilter, setThreatFilter] = useState<string>('All');
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('1h');
  const [timeMenuOpen, setTimeMenuOpen] = useState<boolean>(false);
  const timeMenuRef = useRef<HTMLDivElement>(null);

  // Bug 2 fix: Explicit selection and inspector drawer open/closed state
  const [selectedThreatIndex, setSelectedThreatIndex] = useState<number | null>(0);
  const [isInspectorOpen, setIsInspectorOpen] = useState<boolean>(true);
  const [headersAccordionOpen, setHeadersAccordionOpen] = useState(false);

  // Close menus on click outside
  useEffect(() => {
    if (!timeMenuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (timeMenuRef.current && !timeMenuRef.current.contains(e.target as Node)) {
        setTimeMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [timeMenuOpen]);

  useEffect(() => {
    if (!projectMenuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (projectMenuRef.current && !projectMenuRef.current.contains(e.target as Node)) {
        setProjectMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [projectMenuOpen]);

  // Load Projects (Auth-aware, persists to localStorage to prevent reload context loss)
  useEffect(() => {
    if (!token) {
      setProjects(MOCK_PROJECTS);
      return;
    }

    const loadProjects = async () => {
      try {
        const data = await fetchProjects(token);
        if (data && data.length > 0) {
          setProjects(data);
          try {
            localStorage.setItem('aegis_projects', JSON.stringify(data));
          } catch {
            // ignore storage quota errors
          }
          if (!activeProjectId || !data.some((p) => p._id === activeProjectId)) {
            setActiveProject(data[0]._id);
          }
        } else {
          // Empty project list from backend
          setProjects([]);
          localStorage.removeItem('aegis_projects');
          setActiveProject(null);
        }
      } catch {
        // On network error or offline mode, retain any cached projects
        try {
          const saved = localStorage.getItem('aegis_projects');
          if (saved) {
            const parsed = JSON.parse(saved);
            if (parsed.length > 0) {
              setProjects(parsed);
              if (!activeProjectId) {
                setActiveProject(parsed[0]._id);
              }
            }
          }
        } catch {
          // retain state
        }
      }
    };
    loadProjects();
  }, [token, activeProjectId, setActiveProject]);



  // Prevent premature render or unauthenticated route kick during hydration check
  if (isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <span style={{ color: 'var(--ac)', display: 'inline-flex' }}>
            <ShieldIcon size={32} />
          </span>
          <div style={{ color: 'var(--t2)', fontSize: '13px', fontWeight: 500 }}>Initializing session...</div>
        </div>
      </div>
    );
  }

  // Determine Active Project
  const activeProject = token
    ? (projects.find((p) => p._id === activeProjectId) || projects[0] || null)
    : (projects.find((p) => p._id === activeProjectId) || projects[0] || null);

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
    } catch {
      // Fallback
    }
    showToast('Telemetry flushed');
  };

  // Auth-aware data resolution:
  // If authenticated: strictly live data, NO mock fallbacks
  // If unauthenticated preview: mock fixtures
  const displayJailedList: PrototypeJailItem[] = token ? jailedList : (jailedList.length > 0 ? jailedList : MOCK_JAILED_IPS);
  const displayCircuitBreakers: CircuitBreakerRecord[] = token ? circuitBreakers : (circuitBreakers.length > 0 ? circuitBreakers : MOCK_CIRCUIT_BREAKERS);

  const displayThreats: PrototypeEvent[] = token
    ? (threats && threats.length > 0 ? threats.map(mapThreatRecordToPrototypeEvent) : [])
    : (threats && threats.length > 0 ? threats.map(mapThreatRecordToPrototypeEvent) : MOCK_THREATS);

  // Time Window Filtering (Bug 4)
  const selectedWindowObj = TIME_WINDOWS.find((w) => w.id === timeWindow) || TIME_WINDOWS[1];
  const cutoff = Date.now() - selectedWindowObj.durationMs;

  const filteredThreats = displayThreats.filter((ev) => {
    const matchesSeverity = threatFilter === 'All' || ev.severity.toLowerCase() === threatFilter.toLowerCase();
    if (!matchesSeverity) return false;

    const eventTime = new Date(ev.timestamp).getTime();
    if (!isNaN(eventTime)) {
      return eventTime >= cutoff;
    }
    return true;
  });

  // Bug 2 fix: Selected Event is null when drawer is closed or no valid event is selected
  const selectedEvent =
    isInspectorOpen &&
    selectedThreatIndex !== null &&
    selectedThreatIndex >= 0 &&
    selectedThreatIndex < filteredThreats.length
      ? filteredThreats[selectedThreatIndex]
      : null;

  // Stats KPIs calculation
  const totalBlockedCount = token
    ? (stats?.totalBlocks ?? 0)
    : (stats?.totalBlocks || displayThreats.length || MOCK_METRICS.totalBlocks);

  const criticalThreatCount = token
    ? (stats?.criticalCount ?? 0)
    : (stats?.criticalCount || displayThreats.filter((m) => m.severity.toLowerCase() === 'critical').length || MOCK_METRICS.criticalCount);

  const tripwireCount = token
    ? (displayThreats.filter((m) => m.rule.includes('blocked') || m.rule.includes('sqli') || m.rule.includes('traversal')).length)
    : (displayThreats.filter((m) => m.rule.includes('blocked') || m.rule.includes('sqli') || m.rule.includes('traversal')).length || MOCK_METRICS.tripwireCount);

  const navTabs = [
    { id: 0, label: 'Analytics console' },
    { id: 1, label: 'Tenant provisioning' },
    { id: 2, label: 'Project settings' },
    { id: 3, label: 'DLQ monitor' }
  ];

  return (
    <div className="app">
      {/* HEADER SECTION (Unified block with single bottom border) */}
      <header>
        {/* Top Brand & Context Row (56px high, NO bottom border) */}
        <div className="hd">
          <span style={{ color: 'var(--ac)', display: 'flex' }}>
            <GateIcon size={22} />
          </span>
          <b className="lgt">AegisGate</b>
          <span className="dv"></span>

          {/* Project Selector Button */}
          <div ref={projectMenuRef} style={{ position: 'relative' }}>
            <button
              className="sc sm"
              style={{ display: 'flex', gap: '6px', alignItems: 'center' }}
              onClick={() => setProjectMenuOpen(!projectMenuOpen)}
            >
              Project: {activeProject ? activeProject.projectName : (token ? 'No projects' : 'payments-api')}{' '}
              <CaretDownIcon size={14} />
            </button>

            {/* Project Dropdown Floating Menu */}
            {projectMenuOpen && (
              <div className="menu" style={{ position: 'absolute', top: '38px', left: 0 }}>
                {projects.length > 0 ? (
                  projects.map((p) => {
                    const isActive = activeProject && p._id === activeProject._id;
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
                  })
                ) : (
                  <div style={{ color: 'var(--t3)', padding: '8px 12px', cursor: 'default' }}>
                    No projects provisioned
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Header Navigation Items */}
          <div className="sp">
            {connectionStatus === 'unauthenticated' ? (
              <span className="p" style={{ ['--c' as any]: 'var(--crit)' }}>
                <i></i>Auth required (session expired)
              </span>
            ) : connectionStatus === 'offline' ? (
              <span className="p" style={{ ['--c' as any]: 'var(--crit)' }}>
                <i></i>Offline (waiting for connection)
              </span>
            ) : connectionStatus === 'rate_limited' ? (
              <span className="p" style={{ ['--c' as any]: 'var(--hi)' }}>
                <i></i>Sync paused (rate limited)
              </span>
            ) : connectionStatus === 'reconnecting' ? (
              <span className="p" style={{ ['--c' as any]: 'var(--crit)' }}>
                <i></i>Reconnecting...
              </span>
            ) : (
              <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
                <i></i>Gateway online
              </span>
            )}
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

        {/* Sub-Navigation Tabs Row (48px high with single unified bottom border) */}
        <nav className="tabs">
          {navTabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={isActive ? 'on' : ''}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>
      </header>

      {/* Sample Data Banner when not logged in */}
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
              <div className="kvv">{totalBlockedCount}</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                {token ? 'Cumulative recorded events' : 'up 12.4% vs previous 24h'}
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
              <div className="kvv">{criticalThreatCount}</div>
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
              <div className="kvv">{tripwireCount}</div>
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
              <div className="kvv">p95 4.8 ms</div>
              <div className="cap" style={{ whiteSpace: 'nowrap' }}>
                p50 1.8 ms - p99 8.2 ms - last 24h
              </div>
            </div>
          </div>

          {/* Row 2 — Jailed IPs (60%) & Upstream Circuit Breakers (40%) with items-start alignment (Bug 3) */}
          <div className="row" style={{ gridTemplateColumns: '3fr 2fr', alignItems: 'start' }}>
            {/* Jailed IPs Card - Constrained max height and structural min-height */}
            <div className="card" style={{ minHeight: '440px', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className="ct">Jailed IPs</span>
                <span className="p" style={{ ['--c' as any]: 'var(--low)' }}>
                  {displayJailedList.length} banned
                </span>
              </div>

              <div className="tr h" style={{ gridTemplateColumns: '24px 1fr 1.3fr 90px 80px' }}>
                <span></span>
                <span>Client IP</span>
                <span>Time remaining</span>
                <span>Status</span>
                <span>Action</span>
              </div>

              {/* Scrollable container capped at max-h-[380px] */}
              <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
                {displayJailedList.length > 0 ? (
                  displayJailedList.map((r) => {
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
                  })
                ) : (
                  <div style={{ padding: '48px 16px', textAlign: 'center', color: 'var(--t2)', fontSize: '13px' }}>
                    No active IP bans at the edge.
                  </div>
                )}
              </div>

              <div className="cap" style={{ marginTop: 'auto', paddingTop: '16px' }}>
                Jailed after 3 abuse points within 60 s. Ban lasts 10 minutes.
              </div>
            </div>

            {/* Upstream Circuit Breakers Card - Constrained max height and structural min-height */}
            <div className="card" style={{ minHeight: '440px', display: 'flex', flexDirection: 'column' }}>
              <span className="ct" style={{ marginBottom: '16px' }}>Upstream circuit breakers</span>

              <div style={{ maxHeight: '380px', overflowY: 'auto', display: 'grid', gap: '12px' }}>
                {displayCircuitBreakers.length > 0 ? (
                  displayCircuitBreakers.map((cb) => {
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
                          <div style={{ background: 'var(--card)', borderRadius: '2px', padding: '8px 12px' }}>
                            <div className="cap">In-flight</div>
                            <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{cb.inFlight} / 100</div>
                          </div>
                          <div style={{ background: 'var(--card)', borderRadius: '2px', padding: '8px 12px' }}>
                            <div className="cap">Failures</div>
                            <div style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{cb.consecutiveFailures} / 5</div>
                          </div>
                          <div style={{ background: 'var(--card)', borderRadius: '2px', padding: '8px 12px' }}>
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
                  <div className="in" style={{ padding: '48px 16px', textAlign: 'center', color: 'var(--t2)', fontSize: '13px' }}>
                    No active upstream circuit breakers monitored.
                  </div>
                )}
              </div>

              <div className="cap" style={{ marginTop: 'auto', paddingTop: '16px' }}>
                Bulkhead limit: 100 connections per upstream.
              </div>
            </div>
          </div>

          {/* Row 3 — Live Threat Stream (62%) & Payload Inspector (38%) with items-start alignment (Bug 3) */}
          <div className="row" style={{ gridTemplateColumns: '62fr 38fr', alignItems: 'start' }}>
            {/* Live Threat Stream Card */}
            <div className="card" style={{ minHeight: '520px', display: 'flex', flexDirection: 'column' }}>
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

              {/* Filter Chips & Time Window Selector (Bug 4) */}
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

                {/* Interactive Time Window Selector Popover (Bug 4) */}
                <div ref={timeMenuRef} style={{ marginLeft: 'auto', position: 'relative' }}>
                  <button
                    type="button"
                    className={`ch ${timeMenuOpen ? 'on' : ''}`}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                    onClick={() => setTimeMenuOpen(!timeMenuOpen)}
                    aria-haspopup="true"
                    aria-expanded={timeMenuOpen}
                  >
                    {selectedWindowObj.label} <CaretDownIcon size={14} />
                  </button>

                  {timeMenuOpen && (
                    <div
                      className="menu"
                      style={{
                        position: 'absolute',
                        top: '34px',
                        right: 0,
                        left: 'auto',
                        width: '140px',
                        zIndex: 50
                      }}
                    >
                      {TIME_WINDOWS.map((w) => (
                        <div
                          key={w.id}
                          onClick={() => {
                            setTimeWindow(w.id);
                            setTimeMenuOpen(false);
                            setSelectedThreatIndex(0);
                          }}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            fontWeight: timeWindow === w.id ? 600 : 400
                          }}
                        >
                          <span>{w.label}</span>
                          {timeWindow === w.id && <CheckIcon size={14} />}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Table Header */}
              <div className="tr h" style={{ gridTemplateColumns: '90px 80px 130px 1fr 60px' }}>
                <span>Severity</span>
                <span>Time (UTC)</span>
                <span>Client IP</span>
                <span>Attack type</span>
                <span>Action</span>
              </div>

              {/* Scrollable Threat Rows Capped at 380px */}
              <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
                {filteredThreats.length > 0 ? (
                  filteredThreats.map((r, i) => {
                    const isSelected = isInspectorOpen && selectedThreatIndex === i;
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
                          onClick={() => {
                            setSelectedThreatIndex(i);
                            setIsInspectorOpen(true);
                          }}
                        >
                          Inspect
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ padding: '48px 16px', textAlign: 'center', color: 'var(--t2)', fontSize: '13px' }}>
                    No security tripwire events captured in this window.
                  </div>
                )}
              </div>

              <div className="cap" style={{ display: 'flex', justifyContent: 'space-between', marginTop: 'auto', paddingTop: '16px' }}>
                <span>
                  Showing {filteredThreats.length} of {displayThreats.length} events -{' '}
                  <button type="button" className="lk" onClick={() => setThreatFilter('All')}>
                    View all
                  </button>
                </span>
                <span>Events kept for 30 days</span>
              </div>
            </div>

            {/* Payload Inspector Card (Bug 2 fix: Closes properly on X click) */}
            <div className="card" style={{ minHeight: '520px', display: 'flex', flexDirection: 'column' }}>
              {selectedEvent ? (
                <div style={{ overflowY: 'auto', maxHeight: '460px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px', alignItems: 'center' }}>
                    <span className="ct">Payload inspector</span>
                    <button
                      type="button"
                      onClick={() => {
                        setIsInspectorOpen(false);
                        setSelectedThreatIndex(null);
                      }}
                      style={{
                        cursor: 'pointer',
                        color: 'var(--t3)',
                        background: 'none',
                        border: 'none',
                        padding: '4px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '2px'
                      }}
                      aria-label="Close inspector"
                      title="Close inspector"
                    >
                      <CloseIcon size={16} />
                    </button>
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
                      <span>{selectedEvent.timestamp ? selectedEvent.timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : `2026-10-03 ${selectedEvent.time} UTC`}</span>
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
                </div>
              ) : (
                <div style={{ margin: 'auto', textAlign: 'center', padding: '48px 0' }}>
                  <div className="ct" style={{ marginBottom: '8px' }}>Payload inspector</div>
                  <div className="cap">
                    Select an event to inspect its payload
                  </div>
                </div>
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
            setProjects((prev) => {
              const next = [...prev, newProj];
              try {
                localStorage.setItem('aegis_projects', JSON.stringify(next));
              } catch {
                // ignore
              }
              return next;
            });
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
            setProjects((prev) => {
              const next = prev.map((p) => (p._id === updated._id ? updated : p));
              try {
                localStorage.setItem('aegis_projects', JSON.stringify(next));
              } catch {
                // ignore
              }
              return next;
            });
          }}
        />
      )}

      {/* Screen 4: DLQ Monitor */}
      {activeTab === 3 && (
        <DLQMonitor activeProjectId={activeProject?._id || null} token={token} />
      )}

      {/* FOOTER */}
      <div className="cap" style={{ padding: '8px 40px 24px', fontSize: '12px' }}>
        AegisGate v2.1.0
      </div>

      {/* UNBAN CONFIRMATION MODAL OVERLAY */}
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
