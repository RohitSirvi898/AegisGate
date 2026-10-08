import { useEffect, useState } from 'react';

import { useToast } from '../context/ToastContext';
import { fetchDeadLetterLogs, type DeadLetterLog } from '../services/api';
import { CloseIcon, ShieldCheckIcon } from './Icons';

interface DLQMonitorProps {
  activeProjectId: string | null;
  token: string | null;
}

interface DisplayMessage {
  id: string;
  time: string;
  receivedFull: string;
  reason: string;
  retries: string;
  payload: string;
}

const prototypeMockMessages: DisplayMessage[] = [
  {
    id: 'DLQ-3071',
    time: '13:12:44',
    receivedFull: '2026-10-03 13:12:44 UTC',
    reason: 'Invalid JSON',
    retries: '3 of 3',
    payload: '{"event": "request_blocked", "rule": "sqli.tautology"}'
  },
  {
    id: 'DLQ-3070',
    time: '12:58:02',
    receivedFull: '2026-10-03 12:58:02 UTC',
    reason: 'Schema validation failed',
    retries: '3 of 3',
    payload: '{"event": "request_blocked", "rule": "traversal.dotdot"}'
  },
  {
    id: 'DLQ-3068',
    time: '11:47:19',
    receivedFull: '2026-10-03 11:47:19 UTC',
    reason: 'MongoDB write rejected',
    retries: '3 of 3',
    payload: '{"event": "request_blocked", "rule": "xss.event-handler"}'
  }
];

export default function DLQMonitor({ activeProjectId, token }: DLQMonitorProps) {
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [inspectOpen, setInspectOpen] = useState<boolean>(true);
  const [lastRefreshed, setLastRefreshed] = useState<string>('13:26:02 UTC');
  const [loading, setLoading] = useState<boolean>(false);
  const [isSimulationEmpty, setIsSimulationEmpty] = useState<boolean>(true);

  const { showToast } = useToast();

  const loadData = async () => {
    setLoading(true);
    const now = new Date();
    const utcTime = now.toTimeString().split(' ')[0] + ' UTC';
    setLastRefreshed(utcTime);

    if (activeProjectId && token) {
      try {
        const liveLogs: DeadLetterLog[] = await fetchDeadLetterLogs(activeProjectId, token);
        if (liveLogs && liveLogs.length > 0) {
          const mapped: DisplayMessage[] = liveLogs.map((log) => {
            const timePart = log.timestamp ? log.timestamp.split('T')[1]?.slice(0, 8) || '12:00:00' : '12:00:00';
            return {
              id: log._id ? (log._id.length > 10 ? 'DLQ-' + log._id.slice(-4) : log._id) : 'DLQ-9999',
              time: timePart,
              receivedFull: log.timestamp || `${now.toISOString().split('T')[0]} ${timePart} UTC`,
              reason: log.errorReason || 'Processing failure',
              retries: `${log.retryCount ?? 3} of 3`,
              payload: log.rawBody || JSON.stringify(log.payload || { event: 'request_blocked' }, null, 2)
            };
          });
          setMessages(mapped);
          setIsSimulationEmpty(false);
          setLoading(false);
          return;
        }
      } catch {
        // Fallback to local state
      }
    }

    if (!token || !activeProjectId) {
      setIsSimulationEmpty((prev) => !prev);
    } else {
      setMessages([]);
      setIsSimulationEmpty(true);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (activeProjectId && token) {
      loadData();
    } else {
      setIsSimulationEmpty(true);
    }
  }, [activeProjectId, token]);

  const activeList = token ? messages : (isSimulationEmpty ? [] : prototypeMockMessages);
  const selectedMsg = activeList[selectedIndex] || activeList[0];

  const handleCopyPayload = () => {
    if (selectedMsg) {
      navigator.clipboard?.writeText(selectedMsg.payload);
      showToast('Copied');
    }
  };

  const colGrid = '110px 100px 1fr 70px 60px';

  return (
    <div className="main" style={{ width: '1440px', margin: 'auto' }}>
      {/* Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="pt">Dead-letter queue</div>
          <div style={{ color: 'var(--t2)', marginTop: '4px', whiteSpace: 'nowrap' }}>
            Unprocessable poison messages rejected by the consumer are routed to{' '}
            <span className="in mono" style={{ padding: '2px 6px', borderRadius: '2px' }}>
              aegis.audit.dlq
            </span>
            .
          </div>
        </div>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <span className="cap">Last refreshed {lastRefreshed}</span>
          <button className="sc" onClick={loadData} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Stat card */}
      <div className="card" style={{ width: '320px', display: 'grid', gap: '8px' }}>
        <span style={{ color: 'var(--t2)', fontWeight: 500 }}>Poison messages</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="kvv">{activeList.length}</span>
          {activeList.length === 0 ? (
            <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
              <i></i>Healthy
            </span>
          ) : (
            <span className="p" style={{ ['--c' as any]: 'var(--med)' }}>
              <i></i>Needs review
            </span>
          )}
        </div>
      </div>

      {/* Queue Body */}
      {activeList.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '72px', display: 'grid', gap: '12px', justifyItems: 'center' }}>
          <span style={{ color: 'var(--ok)', display: 'inline-flex' }}>
            <ShieldCheckIcon size={40} />
          </span>
          <span className="p" style={{ ['--c' as any]: 'var(--ok)' }}>
            <i></i>Queue healthy
          </span>
          <div className="ct">No dead-lettered messages</div>
          <div style={{ color: 'var(--t2)' }}>
            All telemetry events are being processed without failures.
          </div>
        </div>
      ) : (
        <div className="row" style={{ gridTemplateColumns: '62fr 38fr' }}>
          {/* Failed Messages Table */}
          <div className="card">
            <div className="ct" style={{ marginBottom: '12px' }}>Failed messages</div>
            <div className="tr h" style={{ gridTemplateColumns: colGrid }}>
              <span>Received (UTC)</span>
              <span>Message ID</span>
              <span>Failure reason</span>
              <span>Retries</span>
              <span>Action</span>
            </div>

            {activeList.map((r, i) => (
              <div
                key={r.id + i}
                className={`tr ${selectedIndex === i && inspectOpen ? 'sel' : ''}`}
                style={{ gridTemplateColumns: colGrid }}
              >
                <span>{r.time}</span>
                <span className="mono">{r.id}</span>
                <span>{r.reason}</span>
                <span>{r.retries}</span>
                <button
                  type="button"
                  className="lk"
                  onClick={() => {
                    setSelectedIndex(i);
                    setInspectOpen(true);
                  }}
                >
                  Inspect
                </button>
              </div>
            ))}

            <div className="cap" style={{ marginTop: '16px' }}>
              Showing {activeList.length} of {activeList.length} messages
            </div>
          </div>

          {/* Inspect Drawer / Details Card */}
          <div className="card" style={{ alignSelf: 'start' }}>
            {inspectOpen && selectedMsg ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px', alignItems: 'center' }}>
                  <span className="ct">Message details</span>
                  <span
                    style={{ cursor: 'pointer', color: 'var(--t3)', display: 'inline-flex' }}
                    onClick={() => setInspectOpen(false)}
                    title="Close details"
                  >
                    <CloseIcon size={16} />
                  </span>
                </div>

                <div style={{ display: 'grid', gap: '10px', marginBottom: '16px' }}>
                  <div className="kv">
                    <span style={{ color: 'var(--t3)' }}>Message ID</span>
                    <span className="mono">{selectedMsg.id}</span>
                  </div>
                  <div className="kv">
                    <span style={{ color: 'var(--t3)' }}>Received</span>
                    <span>{selectedMsg.receivedFull}</span>
                  </div>
                  <div className="kv">
                    <span style={{ color: 'var(--t3)' }}>Failure reason</span>
                    <span>{selectedMsg.reason}</span>
                  </div>
                  <div className="kv">
                    <span style={{ color: 'var(--t3)' }}>Retries</span>
                    <span>{selectedMsg.retries}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <label style={{ margin: 0 }}>Payload (truncated to 2 KB)</label>
                  <button type="button" className="sc sm" onClick={handleCopyPayload}>
                    Copy
                  </button>
                </div>

                <pre className="in mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {selectedMsg.payload}
                </pre>
              </>
            ) : (
              <div className="cap" style={{ padding: '40px 0', textAlign: 'center' }}>
                Select a message to inspect its details
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
