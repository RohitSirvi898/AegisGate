import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Radio, Activity, AlertTriangle, Terminal, Code, Cpu, RefreshCw, Layers, LogOut, LogIn, ChevronDown, Settings, AlertOctagon } from 'lucide-react';
import { useThreatTelemetry, type ThreatRecord } from '../hooks/useThreatTelemetry';
import { useAuth } from '../context/AuthContext';
import ProjectSettings from './ProjectSettings';
import DLQMonitor from './DLQMonitor';
import type { Project } from '../services/api';

export default function Dashboard() {
  const { token, activeProjectId, setActiveProject, logout } = useAuth();
  const navigate = useNavigate();
  
  // Local state to hold the projects list
  const [projects, setProjects] = useState<Project[]>([]);

  const { threats, stats, loading, error, refetch } = useThreatTelemetry(activeProjectId, token);
  const [selectedThreat, setSelectedThreat] = useState<ThreatRecord | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Pre-populated mock data for the simulation console / default view
  const mockThreats: ThreatRecord[] = [
    {
      _id: 'mock_1',
      clientIp: '192.168.1.105',
      endpoint: '/api/v1/payments/checkout',
      method: 'POST',
      timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
      rawBody: '{"cardNumber": "4111********1111", "cvv": "\' OR \'1\'=\'1", "amount": 1000}',
      attackVector: 'SQL Injection',
      severity: 'CRITICAL',
      summary: 'Intercepted malicious SQL characters inside Checkout card number payment handler.'
    },
    {
      _id: 'mock_2',
      clientIp: '45.227.254.12',
      endpoint: '/api/v1/auth/login',
      method: 'POST',
      timestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
      rawBody: '{"username": "admin", "password": "../../../etc/passwd"}',
      attackVector: 'Path Traversal',
      severity: 'HIGH',
      summary: 'Malicious directory traversal string identified within authentication login credentials.'
    },
    {
      _id: 'mock_3',
      clientIp: '89.102.34.88',
      endpoint: '/api/v1/users/profile',
      method: 'GET',
      timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      rawBody: '{"userId": "<script>alert(document.cookie)</script>"}',
      attackVector: 'Cross-Site Scripting (XSS)',
      severity: 'HIGH',
      summary: 'XSS script injection attempt blocked inside profile user ID query parameters.'
    },
    {
      _id: 'mock_4',
      clientIp: '103.44.112.5',
      endpoint: '/api/v1/payments/refund',
      method: 'POST',
      timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      rawBody: '{"refundId": "ref_9921", "amount": -500}',
      attackVector: 'Parameter Tampering',
      severity: 'MEDIUM',
      summary: 'Negative refund amount value rejected in billing ingress proxy endpoint.'
    }
  ];

  const mockStats = {
    totalBlocks: 148,
    criticalCount: 42,
    highCount: 65
  };

  const displayThreats = token ? threats : mockThreats;
  const displayStats = token ? stats : mockStats;
  
  // Compute live security console metrics from database aggregates or mock data
  const totalBlocked = displayStats.totalBlocks;
  const criticalCount = displayStats.criticalCount;
  const highCount = displayStats.highCount;

  // Tab management & Project Provisioning states
  const [activeTab, setActiveTab] = useState<'analytics' | 'provisioning' | 'settings' | 'dlq'>('analytics');
  const [projectName, setProjectName] = useState('');
  const [provisioningLoading, setProvisioningLoading] = useState(false);
  const [provisioningError, setProvisioningError] = useState<string | null>(null);
  const [provisionedProject, setProvisionedProject] = useState<{ _id: string; projectName: string; apiKey: string } | null>(null);

  // Active Project object reference
  const currentProject = projects.find((p) => p._id === activeProjectId) || (projects.length > 0 ? projects[0] : null);

  // Fetch registered user projects when token is present
  useEffect(() => {
    if (!token) return;

    const fetchProjects = async () => {
      try {
        const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/v1/projects`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          setProjects(data);

          // If no active project is set yet, automatically fallback to the first project
          if (data.length > 0 && !activeProjectId) {
            setActiveProject(data[0]._id);
          }
        }
      } catch (err) {
        console.error('❌ Failed to fetch developer projects:', err);
      }
    };

    fetchProjects();
  }, [token, activeProjectId, setActiveProject]);

  // Handle Project update from settings panel
  const handleProjectUpdated = (updated: Project) => {
    setProjects((prev) => prev.map((p) => (p._id === updated._id ? updated : p)));
  };

  // Trigger manual telemetry flush with spin animations
  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await refetch();
    setTimeout(() => setIsRefreshing(false), 800);
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) return;

    setProvisioningLoading(true);
    setProvisioningError(null);
    setProvisionedProject(null);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/v1/projects`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` // Pass JWT authentication
        },
        body: JSON.stringify({ projectName: projectName.trim() }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setProvisionedProject(data);
      
      // Reactive updates: append the new project directly to dropdown projects list
      setProjects((prev) => [...prev, data]);
      setActiveProject(data._id);
      setProjectName('');
    } catch (err: any) {
      setProvisioningError(err.message || 'Failed to provision project.');
    } finally {
      setProvisioningLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#05080f] text-slate-200 font-sans flex flex-col selection:bg-emerald-500 selection:text-black">
      {/* Top Application Command Bar */}
      <header className="border-b border-slate-900 bg-[#080d16]/80 backdrop-blur-md px-6 py-3.5 flex items-center justify-between sticky top-0 z-30 shadow-lg">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center justify-center text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-emerald-400 flex items-center gap-2">
              AEGIS<span className="text-slate-100 font-semibold">GATE</span>
              <span className="text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded border border-slate-700">CORE v1.0.0</span>
            </h1>
            <p className="text-[10px] text-slate-400 tracking-widest uppercase">Edge Security Shield & AI Firewall</p>
          </div>
        </div>

        {/* Real-time System Status Badges */}
        <div className="flex items-center flex-wrap gap-3 text-xs">
          
          {/* Dynamic Project Selector Dropdown Menu */}
          {token && (
            <div className="flex items-center gap-2 bg-[#111927] border border-slate-800 rounded-lg px-3 py-1.5 transition duration-200 shadow-inner group">
              <span className="text-[9px] text-slate-500 uppercase font-bold tracking-wider select-none">Active Project:</span>
              <div className="relative flex items-center gap-1">
                <select
                  value={activeProjectId || ''}
                  onChange={(e) => setActiveProject(e.target.value || null)}
                  className="bg-transparent text-emerald-400 font-bold focus:outline-none cursor-pointer pr-4 appearance-none text-xs hover:text-emerald-300 transition duration-150"
                >
                  {projects.length === 0 ? (
                    <option value="" disabled className="bg-[#0c121e] text-slate-400">-- Create Project --</option>
                  ) : (
                    projects.map((proj) => (
                      <option key={proj._id} value={proj._id} className="bg-[#0c121e] text-slate-200 font-mono">
                        {proj.projectName}
                      </option>
                    ))
                  )}
                </select>
                <ChevronDown className="w-3.5 h-3.5 text-emerald-500/80 absolute right-0 pointer-events-none group-hover:text-emerald-400 transition duration-150" />
              </div>
            </div>
          )}

          {error && (
            <div className="bg-amber-500/10 text-amber-400 border border-amber-500/30 px-3 py-1.5 rounded flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 animate-pulse" />
              <span>{error}</span>
            </div>
          )}

          <div className="bg-[#111927] border border-slate-800 px-3 py-1.5 rounded flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span className="text-slate-400">Status:</span>
            <span className="text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1">
              Active <span className="inline-block w-1.5 h-1.5 bg-emerald-400 rounded-full"></span>
            </span>
          </div>

          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="bg-[#111927] hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1.5 rounded transition duration-200 flex items-center gap-2 disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`} />
            <span>Telemetry Flush</span>
          </button>

          {!token ? (
            <button
              onClick={() => navigate('/auth')}
              className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/35 hover:border-emerald-500/50 px-3 py-1.5 rounded transition duration-200 flex items-center gap-2 cursor-pointer font-bold uppercase tracking-wider shadow-[0_0_10px_rgba(16,185,129,0.1)] hover:shadow-[0_0_15px_rgba(16,185,129,0.2)]"
            >
              <LogIn className="w-3.5 h-3.5 text-emerald-400" />
              <span>Sign In</span>
            </button>
          ) : (
            <button
              onClick={logout}
              className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/35 hover:border-red-500/50 px-3 py-1.5 rounded transition duration-200 flex items-center gap-2 cursor-pointer font-bold uppercase tracking-wider"
            >
              <LogOut className="w-3.5 h-3.5 text-red-400" />
              <span>Log Out</span>
            </button>
          )}
        </div>
      </header>

      {/* Top Navigation Tab Bar */}
      <div className="border-b border-slate-900 bg-[#080d16]/90 px-6 py-2.5 flex gap-3 text-xs z-20 overflow-x-auto">
        <button
          onClick={() => setActiveTab('analytics')}
          className={`px-4 py-2 rounded transition duration-200 uppercase tracking-widest font-semibold flex items-center gap-2 border cursor-pointer ${
            activeTab === 'analytics'
              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/35 shadow-[0_0_8px_rgba(16,185,129,0.1)]'
              : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-850'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Analytics Console</span>
        </button>
        <button
          onClick={() => {
            setActiveTab('provisioning');
            setProvisionedProject(null);
          }}
          className={`px-4 py-2 rounded transition duration-200 uppercase tracking-widest font-semibold flex items-center gap-2 border cursor-pointer ${
            activeTab === 'provisioning'
              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/35 shadow-[0_0_8px_rgba(16,185,129,0.1)]'
              : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-850'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          <span>Tenant Provisioning</span>
        </button>
        <button
          onClick={() => setActiveTab('settings')}
          className={`px-4 py-2 rounded transition duration-200 uppercase tracking-widest font-semibold flex items-center gap-2 border cursor-pointer ${
            activeTab === 'settings'
              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/35 shadow-[0_0_8px_rgba(16,185,129,0.1)]'
              : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-850'
          }`}
        >
          <Settings className="w-3.5 h-3.5" />
          <span>Project Settings</span>
        </button>
        <button
          onClick={() => setActiveTab('dlq')}
          className={`px-4 py-2 rounded transition duration-200 uppercase tracking-widest font-semibold flex items-center gap-2 border cursor-pointer ${
            activeTab === 'dlq'
              ? 'text-rose-400 bg-rose-500/10 border-rose-500/35 shadow-[0_0_8px_rgba(244,63,94,0.1)]'
              : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-850'
          }`}
        >
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>DLQ Monitor</span>
        </button>
      </div>

      {/* Main Core Dashboard Grid */}
      <main className="flex-1 p-6 flex flex-col gap-6 max-w-7xl w-full mx-auto z-10">
        {activeTab === 'analytics' && (
          <>
            {!token && (
              <div className="bg-emerald-500/5 border border-emerald-500/20 px-4 py-3.5 rounded-xl flex items-center justify-between text-xs text-emerald-400/90 leading-relaxed shadow-[0_0_10px_rgba(16,185,129,0.05)] border-l-4 border-l-emerald-500 gap-4">
                <div className="flex items-center gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-emerald-400 shrink-0 animate-pulse" />
                  <span>
                    <strong>Console Simulation Mode:</strong> You are viewing pre-populated security telemetry records. Establish an active developer session to configure custom environments, inspect live MongoDB threat logs, and isolate tenancy.
                  </span>
                </div>
                <button
                  onClick={() => navigate('/auth')}
                  className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/35 px-4 py-2 rounded-lg transition duration-150 font-bold uppercase tracking-wider cursor-pointer shadow-[0_0_8px_rgba(16,185,129,0.1)] whitespace-nowrap"
                >
                  Sign In
                </button>
              </div>
            )}

            {/* Row 1: Key Telemetry Summary Indicators */}
            <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
              
              {/* Card 1: Absolute Blocked Events */}
              <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between shadow-[0_4px_20px_rgba(0,0,0,0.15)]">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-widest">Total Blocked events</p>
                  {loading ? (
                    <div className="h-10 w-24 bg-slate-800 animate-pulse rounded mt-2"></div>
                  ) : (
                    <h3 className="text-3xl font-extrabold text-slate-100 mt-1">{totalBlocked}</h3>
                  )}
                  <span className="text-[10px] text-emerald-400 mt-2 inline-block font-semibold">↑ 12.4% vs past 24h</span>
                </div>
                <div className="w-12 h-12 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center justify-center text-red-400">
                  <Activity className="w-6 h-6" />
                </div>
              </div>

              {/* Card 2: Critical Vector Threats */}
              <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between shadow-[0_4px_20px_rgba(0,0,0,0.15)]">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-widest">Critical Vector Threats</p>
                  {loading ? (
                    <div className="h-10 w-24 bg-slate-800 animate-pulse rounded mt-2"></div>
                  ) : (
                    <h3 className="text-3xl font-extrabold text-red-400 mt-1">{criticalCount}</h3>
                  )}
                  <span className="text-[10px] text-red-400/80 mt-2 inline-block font-semibold">Immediate intervention recommended</span>
                </div>
                <div className="w-12 h-12 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center justify-center text-red-400">
                  <AlertTriangle className="w-6 h-6" />
                </div>
              </div>

              {/* Card 3: High Risk Anomaly Vectors */}
              <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between shadow-[0_4px_20px_rgba(0,0,0,0.15)]">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-widest">High Risk Anomaly Vectors</p>
                  {loading ? (
                    <div className="h-10 w-24 bg-slate-800 animate-pulse rounded mt-2"></div>
                  ) : (
                    <h3 className="text-3xl font-extrabold text-amber-400 mt-1">{highCount}</h3>
                  )}
                  <span className="text-[10px] text-amber-400/80 mt-2 inline-block font-semibold">Automated structural blocks engaged</span>
                </div>
                <div className="w-12 h-12 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-center text-amber-400">
                  <Cpu className="w-6 h-6" />
                </div>
              </div>

              {/* Card 4: Inference Latency Average */}
              <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between shadow-[0_4px_20px_rgba(0,0,0,0.15)]">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-widest">Avg ML Inference Speed</p>
                  <h3 className="text-3xl font-extrabold text-emerald-400 mt-1">1.82 <span className="text-sm font-normal text-slate-400">ms</span></h3>
                  <span className="text-[10px] text-slate-400 mt-2 inline-block">Zero performance penalty to user pipeline</span>
                </div>
                <div className="w-12 h-12 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center text-emerald-400">
                  <Terminal className="w-6 h-6" />
                </div>
              </div>
            </section>

            {/* Row 2: Live Security Telemetry Log Table */}
            <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-[#0c121e]/80 border border-slate-800/80 rounded-xl overflow-hidden flex flex-col shadow-xl">
                <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-400" />
                    <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Live Security Threat Telemetry Stream</h2>
                  </div>
                  <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">Realtime Buffer (Last 50)</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-[#080d16] border-b border-slate-800 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Client IP</th>
                        <th className="py-3 px-4">Attack Vector</th>
                        <th className="py-3 px-4 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {displayThreats.map((threat) => (
                        <tr 
                          key={threat._id} 
                          onClick={() => setSelectedThreat(threat)}
                          className={`hover:bg-slate-800/40 transition duration-150 cursor-pointer ${
                            selectedThreat?._id === threat._id ? 'bg-slate-800/60 border-l-2 border-l-emerald-400' : ''
                          }`}
                        >
                          <td className="py-3.5 px-4 font-mono font-bold">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              threat.severity === 'CRITICAL' 
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30' 
                                : threat.severity === 'HIGH'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                : 'bg-slate-800 text-slate-300'
                            }`}>
                              {threat.severity}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                            {new Date(threat.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-3.5 px-4 font-mono text-slate-300">{threat.clientIp}</td>
                          <td className="py-3.5 px-4 font-medium text-slate-200">{threat.attackVector}</td>
                          <td className="py-3.5 px-4 text-right text-emerald-400 font-mono hover:underline">
                            Inspect →
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Threat Detail & Raw Payload Deep Inspection Console */}
              <div className="bg-[#0c121e]/80 border border-slate-800/80 rounded-xl p-5 flex flex-col gap-4 shadow-xl">
                <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
                  <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    Threat Payload Inspector
                  </h3>
                  {selectedThreat && (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      ID: {selectedThreat._id.slice(-6)}
                    </span>
                  )}
                </div>

                {selectedThreat ? (
                  <div className="flex flex-col gap-4 text-xs">
                    <div className="flex flex-col gap-1 bg-[#05080f] p-3 rounded border border-slate-850">
                      <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">AI Security Summary</span>
                      <p className="text-slate-200 leading-relaxed font-sans mt-1">{selectedThreat.summary}</p>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-slate-300">
                      <div className="bg-[#05080f] p-2.5 rounded border border-slate-850 font-mono">
                        <span className="text-slate-500 text-[9px] block uppercase">HTTP Method</span>
                        <span className="font-bold text-emerald-400">{selectedThreat.method}</span>
                      </div>
                      <div className="bg-[#05080f] p-2.5 rounded border border-slate-850 font-mono">
                        <span className="text-slate-500 text-[9px] block uppercase">Vector Category</span>
                        <span className="font-bold text-slate-200">{selectedThreat.attackVector}</span>
                      </div>
                    </div>

                    <div className="bg-[#05080f] p-2.5 rounded border border-slate-850 font-mono text-[11px]">
                      <span className="text-slate-500 text-[9px] block uppercase mb-1">Target Endpoint</span>
                      <span className="text-slate-200 break-all">{selectedThreat.endpoint}</span>
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider">Intercepted Raw JSON Payload</span>
                      <pre className="bg-[#04060a] text-emerald-400 p-3 rounded border border-slate-850 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner max-h-48">
                        {selectedThreat.rawBody || 'No payload body supplied'}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center text-center py-12 text-slate-500 gap-2">
                    <Layers className="w-8 h-8 stroke-1 text-slate-600" />
                    <p className="text-xs">Select any threat record from the stream table to inspect deep payload telemetry.</p>
                  </div>
                )}
              </div>
            </section>
          </>
        )}

        {activeTab === 'provisioning' && (
          <section className="bg-[#0c121e]/80 border border-slate-800/80 rounded-xl p-6 flex flex-col gap-6 max-w-2xl mx-auto w-full shadow-xl">
            <div className="border-b border-slate-800 pb-4">
              <h2 className="text-base font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                <Code className="w-5 h-5 text-emerald-400" />
                Multi-Tenant Environment Provisioning
              </h2>
              <p className="text-xs text-slate-400 mt-1">Register new application tenants to provision cryptographically signed API access keys.</p>
            </div>

            <form onSubmit={handleCreateProject} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label htmlFor="projectName" className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Project Environment Name
                </label>
                <input
                  type="text"
                  id="projectName"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  placeholder="e.g. Production Payment Portal"
                  disabled={provisioningLoading}
                  className="bg-slate-900 border border-slate-800 focus:border-emerald-500/50 rounded px-4 py-2.5 text-slate-100 placeholder-slate-600 text-sm focus:outline-none transition duration-200 font-mono"
                />
              </div>
              
              {provisioningError && (
                <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-2 rounded font-semibold flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 animate-pulse" />
                  <span>{provisioningError}</span>
                </p>
              )}

              <button
                type="submit"
                disabled={provisioningLoading || !projectName.trim()}
                className="bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-40 disabled:hover:bg-emerald-500/10 text-emerald-400 font-bold uppercase text-xs tracking-widest border border-emerald-500/35 shadow-[0_0_8px_rgba(16,185,129,0.1)] rounded py-3 transition duration-200 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
              >
                {provisioningLoading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Provisioning Environment...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-3.5 h-3.5" />
                    <span>Generate API Keys</span>
                  </>
                )}
              </button>
            </form>

            {/* Success View */}
            {provisionedProject && (
              <div className="bg-slate-900/60 p-5 rounded-lg border border-emerald-500/20 flex flex-col gap-4 mt-2 transition-all duration-300">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase tracking-wider">
                  <Shield className="w-4 h-4" />
                  <span>Project Environment Provisioned Successfully!</span>
                </div>
                
                <div className="flex flex-col gap-1">
                  <span className="text-slate-500 text-[10px] uppercase">Project Name</span>
                  <span className="text-slate-200 text-sm font-semibold">{provisionedProject.projectName}</span>
                </div>

                <div className="flex flex-col gap-1.5">
                  <span className="text-slate-500 text-[10px] uppercase">Project ID (projectId)</span>
                  <div className="flex items-center justify-between bg-[#05080f] px-3.5 py-2.5 rounded border border-slate-850 font-mono text-xs text-slate-300 select-all group relative">
                    <span className="break-all">{provisionedProject._id}</span>
                  </div>
                </div>

                <div className="flex flex-col gap-1.5">
                  <span className="text-slate-500 text-[10px] uppercase">API Access Key (apiKey)</span>
                  <div className="flex items-center justify-between bg-[#05080f] px-3.5 py-2.5 rounded border border-slate-850 font-mono text-xs text-emerald-400 select-all border-l-2 border-l-emerald-500 shadow-inner group relative border-emerald-500/40">
                    <span className="break-all font-bold">{provisionedProject.apiKey}</span>
                  </div>
                  <span className="text-[10px] text-amber-500/80 font-semibold mt-1">⚠️ IMPORTANT: Store this key safely. For security reasons, it cannot be recovered or viewed again.</span>
                </div>
              </div>
            )}
          </section>
        )}

        {activeTab === 'settings' && (
          <ProjectSettings
            activeProject={currentProject}
            token={token}
            onProjectUpdated={handleProjectUpdated}
          />
        )}

        {activeTab === 'dlq' && (
          <DLQMonitor
            activeProjectId={activeProjectId}
            token={token}
          />
        )}
      </main>

      {/* Cyber Command Footer */}
      <footer className="border-t border-slate-850 bg-[#080d16] px-6 py-3.5 text-center text-[10px] text-slate-500 uppercase tracking-widest flex justify-between">
        <span>🔒 AEGisGATE Edge Command Terminal</span>
        <span>All systems active</span>
      </footer>
    </div>
  );
}
