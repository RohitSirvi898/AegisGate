import { useState } from 'react';
import { Shield, Radio, Activity, AlertTriangle, Terminal, Code, Cpu, RefreshCw, Layers } from 'lucide-react';
import { useThreatTelemetry, type ThreatRecord } from './hooks/useThreatTelemetry';

export default function App() {
  const { threats, stats, loading, error, refetch } = useThreatTelemetry();
  const [selectedThreat, setSelectedThreat] = useState<ThreatRecord | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Compute live security console metrics from database aggregates
  const totalBlocked = stats.totalBlocks;
  const criticalCount = stats.criticalCount;
  const highCount = stats.highCount;


  // Tab management & Project Provisioning states
  const [activeTab, setActiveTab] = useState<'analytics' | 'provisioning'>('analytics');
  const [projectName, setProjectName] = useState('');
  const [provisioningLoading, setProvisioningLoading] = useState(false);
  const [provisioningError, setProvisioningError] = useState<string | null>(null);
  const [provisionedProject, setProvisionedProject] = useState<{ _id: string; projectName: string; apiKey: string } | null>(null);

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
        },
        body: JSON.stringify({ projectName: projectName.trim() }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setProvisionedProject(data);
      setProjectName(''); // Reset input
    } catch (err: any) {
      console.error('❌ Failed to provision project:', err);
      setProvisioningError(err.message || 'Network error occurred. Failed to connect to provisioning gateway.');
    } finally {
      setProvisioningLoading(false);
    }
  };


  const criticalAndHighCount = criticalCount + highCount;

  return (
    <div className="min-h-screen bg-[#070b13] text-slate-100 flex flex-col font-mono relative overflow-hidden">
      {/* Cybersecurity scanline background mesh */}
      <div className="absolute inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,24,38,0.8)_50%,rgba(11,15,25,0.8)_50%)] bg-[length:100%_4px]"></div>

      {/* Top Cybersecurity Command Header */}
      <header className="border-b border-slate-800 bg-[#0c121e]/85 backdrop-blur-md sticky top-0 z-30 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/35 cyber-glow-emerald">
            <Shield className="w-6 h-6 text-emerald-400" />
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
            className="bg-[#111927] hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 px-3 py-1.5 rounded transition duration-200 flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`} />
            <span>Telemetry Flush</span>
          </button>
        </div>
      </header>

      {/* Top Navigation Tab Bar for multi-tenancy provisioning and analytics */}
      <div className="border-b border-slate-900 bg-[#080d16]/90 px-6 py-2.5 flex gap-4 text-xs z-20">
        <button
          onClick={() => setActiveTab('analytics')}
          className={`px-4 py-2 rounded transition duration-200 uppercase tracking-widest font-semibold flex items-center gap-2 border cursor-pointer ${
            activeTab === 'analytics'
              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/35 cyber-glow-emerald'
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
              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/35 cyber-glow-emerald'
              : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-850'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          <span>Tenant Provisioning</span>
        </button>
      </div>

      {/* Main Core Dashboard Grid */}
      <main className="flex-1 p-6 flex flex-col gap-6 max-w-7xl w-full mx-auto z-10">
        {activeTab === 'analytics' ? (
          <>

        
        {/* Row 1: Key Telemetry Summary Indicators */}
        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          
          {/* Card 1: Absolute Blocked Events */}
          <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest">Total Blocked events</p>
              {loading ? (
                <div className="h-10 w-24 bg-slate-800 animate-pulse rounded mt-2"></div>
              ) : (
                <h3 className="text-3xl font-extrabold text-slate-100 mt-1">{totalBlocked}</h3>
              )}
              <p className="text-[10px] text-emerald-400 mt-2 flex items-center gap-1">
                <Activity className="w-3 h-3" />
                <span>100% Protection Ratio</span>
              </p>
            </div>
            <div className="bg-emerald-500/10 p-3 rounded-lg border border-emerald-500/20 cyber-glow-emerald">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
          </div>

          {/* Card 2: Severe Threat Flags */}
          <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest">Severe threat flags</p>
              {loading ? (
                <div className="h-10 w-24 bg-slate-800 animate-pulse rounded mt-2"></div>
              ) : (
                <h3 className="text-3xl font-extrabold text-red-500 mt-1">{criticalAndHighCount}</h3>
              )}
              <p className="text-[10px] text-red-400 mt-2 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                <span>{criticalCount} Critical, {highCount} High</span>
              </p>
            </div>
            <div className="bg-red-500/10 p-3 rounded-lg border border-red-500/20 cyber-glow-crimson">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
          </div>

          {/* Card 3: Cache / Middleware Layer */}
          <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest">Distributed cache</p>
              <h3 className="text-3xl font-extrabold text-emerald-400 mt-1">REDIS</h3>
              <p className="text-[10px] text-emerald-400 mt-2 flex items-center gap-1">
                <Layers className="w-3 h-3" />
                <span>Rate-Limit Store Online</span>
              </p>
            </div>
            <div className="bg-emerald-500/10 p-3 rounded-lg border border-emerald-500/20">
              <Layers className="w-6 h-6 text-emerald-400" />
            </div>
          </div>

          {/* Card 4: Hardware / Edge Anomaly Engine */}
          <div className="bg-[#0c121e]/70 border border-slate-800/80 rounded-xl p-5 relative overflow-hidden flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-widest">Anomaly Detection Engine</p>
              <h3 className="text-3xl font-extrabold text-emerald-400 mt-1">ISOF</h3>
              <p className="text-[10px] text-slate-400 mt-2 flex items-center gap-1">
                <Cpu className="w-3 h-3 text-emerald-400" />
                <span>Isolation Forest Active</span>
              </p>
            </div>
            <div className="bg-emerald-500/10 p-3 rounded-lg border border-emerald-500/20">
              <Cpu className="w-6 h-6 text-emerald-400" />
            </div>
          </div>

        </section>

        {/* Row 2: Live Attack Stream & Code Inspector Grid */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 items-stretch">
          
          {/* Component: Live Attack Stream */}
          <div className="bg-[#0c121e]/80 border border-slate-800 rounded-xl p-5 lg:col-span-2 flex flex-col min-h-[450px]">
            <div className="flex items-center justify-between border-b border-slate-850 pb-4 mb-4">
              <h2 className="text-sm font-bold uppercase tracking-widest text-emerald-400 flex items-center gap-2">
                <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
                <span>Live Blocked Attack Stream</span>
              </h2>
              <span className="text-[10px] text-slate-500">Auto-refreshing every 5s</span>
            </div>

            {loading ? (
              <div className="flex-1 flex flex-col justify-center items-center gap-3">
                <RefreshCw className="w-8 h-8 text-slate-600 animate-spin" />
                <span className="text-slate-500 text-xs uppercase tracking-widest">Awaiting Live Telemetry Streams...</span>
              </div>
            ) : (
              <div className="flex-1 overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-800">
                      <th className="pb-3 pr-2 font-medium uppercase">Timestamp</th>
                      <th className="pb-3 px-2 font-medium uppercase">Source IP</th>
                      <th className="pb-3 px-2 font-medium uppercase">Target Path</th>
                      <th className="pb-3 px-2 font-medium uppercase">Attack Vector</th>
                      <th className="pb-3 pl-2 font-medium uppercase text-right">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850">
                    {threats.map((threat) => {
                      // Determine severity label colors dynamically
                      const severityColors = 
                        threat.severity === 'CRITICAL' ? 'text-red-500 bg-red-500/10 border-red-500/35 cyber-glow-crimson font-bold' :
                        threat.severity === 'HIGH' ? 'text-rose-400 bg-rose-500/10 border-rose-500/30' :
                        threat.severity === 'MEDIUM' ? 'text-amber-500 bg-amber-500/10 border-amber-500/30' :
                        'text-slate-400 bg-slate-800/10 border-slate-700/30';

                      const isSelected = selectedThreat?._id === threat._id;

                      return (
                        <tr
                          key={threat._id}
                          onClick={() => setSelectedThreat(threat)}
                          className={`hover:bg-[#161e2e]/45 cursor-pointer border-b border-slate-850 transition duration-150 ${isSelected ? 'bg-[#182335]/70 border-l-2 border-l-emerald-400' : ''}`}
                        >
                          <td className="py-3 pr-2 text-slate-400 whitespace-nowrap">
                            {new Date(threat.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-3 px-2 text-slate-200 font-semibold">{threat.clientIp}</td>
                          <td className="py-3 px-2 whitespace-nowrap">
                            <span className="text-slate-400 mr-1.5">{threat.method}</span>
                            <span className="text-slate-200">{threat.endpoint}</span>
                          </td>
                          <td className="py-3 px-2 text-emerald-400 font-semibold">{threat.attackVector}</td>
                          <td className="py-3 pl-2 text-right">
                            <span className={`inline-block text-[9px] px-2 py-0.5 rounded border ${severityColors}`}>
                              {threat.severity}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Component: Payload & Intelligence Inspector */}
          <div className="bg-[#0c121e]/80 border border-slate-800 rounded-xl p-5 flex flex-col min-h-[450px]">
            <div className="flex items-center gap-2 border-b border-slate-850 pb-4 mb-4 text-sm font-bold uppercase tracking-widest text-emerald-400">
              <Terminal className="w-4 h-4" />
              <span>Telemetry Code Inspector</span>
            </div>

            {selectedThreat ? (
              <div className="flex-1 flex flex-col justify-between gap-4">
                <div className="space-y-3.5">
                  <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-xs">
                    <span className="text-slate-400 block uppercase text-[10px] tracking-wider mb-1">Intelligence Summary</span>
                    <p className="text-slate-200 font-semibold leading-relaxed">{selectedThreat.summary}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-850">
                      <span className="text-slate-500 block uppercase text-[9px] mb-0.5">Origin Source</span>
                      <span className="text-slate-300 font-semibold">{selectedThreat.clientIp}</span>
                    </div>
                    <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-850">
                      <span className="text-slate-500 block uppercase text-[9px] mb-0.5">Classification</span>
                      <span className="text-emerald-400 font-semibold">{selectedThreat.attackVector}</span>
                    </div>
                  </div>

                  {selectedThreat.rawBody && (
                    <div className="flex flex-col flex-1">
                      <span className="text-slate-400 uppercase text-[10px] tracking-wider mb-1.5 flex items-center gap-1.5">
                        <Code className="w-3.5 h-3.5" />
                        <span>Intercepted Raw Payload Payload</span>
                      </span>
                      <div className="bg-[#05080f] p-3.5 rounded-lg border border-slate-850 overflow-x-auto text-[11px] font-mono text-red-400 max-h-[220px] overflow-y-auto leading-relaxed border-l-2 border-l-red-500 shadow-inner">
                        <pre className="whitespace-pre-wrap break-all">{selectedThreat.rawBody}</pre>
                      </div>
                    </div>
                  )}
                </div>

                <div className="text-[10px] text-slate-500 border-t border-slate-850 pt-3 flex items-center justify-between">
                  <span>ID: {selectedThreat._id}</span>
                  <span>System Log Verified</span>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col justify-center items-center gap-3 text-slate-500 text-center px-4">
                <Code className="w-8 h-8 text-slate-700" />
                <p className="text-xs uppercase tracking-wider">Select a blocked threat record row to inspect metadata payload string footprint.</p>
              </div>
            )}
          </div>

        </section>
      </>
    ) : (
      <section className="flex-1 max-w-2xl w-full mx-auto bg-[#0c121e]/80 border border-slate-800 rounded-xl p-6 flex flex-col gap-6 shadow-2xl">
        <div className="border-b border-slate-850 pb-4">
          <h2 className="text-sm font-bold uppercase tracking-widest text-emerald-400 flex items-center gap-2">
            <Code className="w-4 h-4" />
            <span>Multi-Tenant Developer Provisioning</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">Register a new project environment to acquire isolated API keys and separate telemetry metrics streams.</p>
        </div>

        {/* Form block */}
        <form onSubmit={handleCreateProject} className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <label htmlFor="projectName" className="text-xs text-slate-400 uppercase tracking-wider">Project Name</label>
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
            className="bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-40 disabled:hover:bg-emerald-500/10 text-emerald-400 font-bold uppercase text-xs tracking-widest border border-emerald-500/35 cyber-glow-emerald rounded py-3 transition duration-200 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
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
              <div className="flex items-center justify-between bg-[#05080f] px-3.5 py-2.5 rounded border border-slate-850 font-mono text-xs text-emerald-400 select-all border-l-2 border-l-emerald-500 shadow-inner group relative">
                <span className="break-all font-bold">{provisionedProject.apiKey}</span>
              </div>
              <span className="text-[10px] text-amber-500/80 font-semibold mt-1">⚠️ IMPORTANT: Store this key safely. For security reasons, it cannot be recovered or viewed again.</span>
            </div>
          </div>
        )}
      </section>
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
