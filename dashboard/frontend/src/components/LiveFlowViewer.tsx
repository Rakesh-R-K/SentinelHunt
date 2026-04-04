import React, { useState, useEffect, useRef } from 'react';

// ==========================================
// Live Flow Viewer Component
// ==========================================
// Real-time stream of network flows with anomaly highlighting.
// Connects via WebSocket for live updates.

interface FlowEntry {
  _stream_id?: string;
  timestamp?: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_count?: number;
  total_bytes?: number;
  severity?: string;
  threat_label?: string;
  final_threat_score?: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const LiveFlowViewer: React.FC = () => {
  const [flows, setFlows] = useState<FlowEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial data from API
  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await fetch('http://localhost:5000/api/flows?limit=100&suspicious_only=true');
        if (res.ok) {
          const data = await res.json();
          setFlows(data.data?.slice(0, 50) || []);
        }
      } catch (e) {
        console.error('Failed to fetch flows:', e);
      }
    };
    fetchFlows();
  }, []);

  // WebSocket connection for live updates
  useEffect(() => {
    let socket: any = null;

    const connectWS = async () => {
      try {
        // Dynamically import socket.io-client
        const { io } = await import('socket.io-client');
        socket = io('http://localhost:5000', {
          transports: ['websocket', 'polling'],
          reconnection: true,
          reconnectionDelay: 2000,
        });

        socket.on('connect', () => {
          setConnected(true);
          socket.emit('subscribe:alerts');
        });

        socket.on('new:alert', (alert: FlowEntry) => {
          if (!paused) {
            setFlows(prev => {
              const updated = [alert, ...prev].slice(0, 200);
              return updated;
            });
          }
        });

        socket.on('disconnect', () => setConnected(false));

        wsRef.current = socket;
      } catch (e) {
        console.log('WebSocket not available, using polling');
      }
    };

    connectWS();

    return () => {
      if (socket) socket.disconnect();
    };
  }, [paused]);

  const filteredFlows = flows.filter(flow => {
    if (!filter) return true;
    const searchStr = JSON.stringify(flow).toLowerCase();
    return searchStr.includes(filter.toLowerCase());
  });

  const formatTime = (ts?: string) => {
    if (!ts) return '--:--:--';
    try {
      return new Date(ts).toLocaleTimeString();
    } catch {
      return ts.substring(11, 19);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>
          <span style={{
            display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%',
            backgroundColor: connected ? '#22c55e' : '#64748b', marginRight: '8px',
            boxShadow: connected ? '0 0 8px #22c55e' : 'none',
          }} />
          Live Flow Stream
        </h2>
        <div style={styles.controls}>
          <input
            type="text"
            placeholder="Filter flows..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={styles.filterInput}
          />
          <button
            style={{ ...styles.controlBtn, backgroundColor: paused ? '#ef4444' : '#22c55e' }}
            onClick={() => setPaused(!paused)}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <span style={styles.flowCount}>
            {filteredFlows.length} flows
          </span>
        </div>
      </div>

      <div style={styles.tableHeader}>
        <span style={{ ...styles.col, width: '70px' }}>TIME</span>
        <span style={{ ...styles.col, width: '130px' }}>SOURCE</span>
        <span style={{ ...styles.col, width: '130px' }}>DESTINATION</span>
        <span style={{ ...styles.col, width: '50px' }}>PROTO</span>
        <span style={{ ...styles.col, width: '70px' }}>PKTS</span>
        <span style={{ ...styles.col, width: '80px' }}>BYTES</span>
        <span style={{ ...styles.col, width: '70px' }}>SEVERITY</span>
        <span style={{ ...styles.col, flex: 1 }}>LABEL</span>
      </div>

      <div ref={scrollRef} style={styles.flowList}>
        {filteredFlows.map((flow, idx) => {
          const sevColor = SEVERITY_COLORS[flow.severity || ''] || 'transparent';
          const isAnomaly = flow.severity === 'CRITICAL' || flow.severity === 'HIGH';
          return (
            <div
              key={flow._stream_id || idx}
              style={{
                ...styles.flowRow,
                backgroundColor: isAnomaly
                  ? `${sevColor}10`
                  : idx % 2 === 0 ? 'rgba(0,0,0,0.1)' : 'transparent',
                borderLeftColor: sevColor,
                animation: idx === 0 && connected ? 'fadeIn 0.3s ease' : 'none',
              }}
            >
              <span style={{ ...styles.col, width: '70px', fontSize: '11px', color: '#64748b' }}>
                {formatTime(flow.timestamp)}
              </span>
              <span style={{ ...styles.col, width: '130px' }}>
                <span style={styles.ipText}>{flow.src_ip}</span>
                <span style={styles.portText}>:{flow.src_port}</span>
              </span>
              <span style={{ ...styles.col, width: '130px' }}>
                <span style={styles.ipText}>{flow.dst_ip}</span>
                <span style={styles.portText}>:{flow.dst_port}</span>
              </span>
              <span style={{ ...styles.col, width: '50px' }}>
                <span style={styles.protoBadge}>{flow.protocol}</span>
              </span>
              <span style={{ ...styles.col, width: '70px', color: '#94a3b8' }}>
                {flow.packet_count || '-'}
              </span>
              <span style={{ ...styles.col, width: '80px', color: '#94a3b8' }}>
                {flow.total_bytes ? formatBytes(flow.total_bytes) : '-'}
              </span>
              <span style={{ ...styles.col, width: '70px' }}>
                {flow.severity && (
                  <span style={{
                    ...styles.sevBadge,
                    color: sevColor,
                    backgroundColor: `${sevColor}15`,
                    borderColor: `${sevColor}30`,
                  }}>
                    {flow.severity}
                  </span>
                )}
              </span>
              <span style={{
                ...styles.col, flex: 1, fontSize: '11px',
                color: isAnomaly ? sevColor : '#64748b',
                fontWeight: isAnomaly ? 600 : 400,
              }}>
                {flow.threat_label || '-'}
              </span>
            </div>
          );
        })}

        {filteredFlows.length === 0 && (
          <div style={styles.emptyState}>
            {connected ? 'Waiting for live flows...' : 'No flow data available. Start the collector to see live traffic.'}
          </div>
        )}
      </div>
    </div>
  );
};

function formatBytes(bytes: number | string): string {
  const b = typeof bytes === 'string' ? parseInt(bytes) : bytes;
  if (isNaN(b)) return '-';
  if (b < 1024) return `${b}B`;
  if (b < 1048576) return `${(b / 1024).toFixed(0)}K`;
  return `${(b / 1048576).toFixed(1)}M`;
}

const styles: Record<string, React.CSSProperties> = {
  container: { padding: '24px 0' },
  header: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    marginBottom: '16px', flexWrap: 'wrap' as const, gap: '12px',
  },
  title: {
    margin: 0, fontSize: '20px', fontWeight: 700, color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace', display: 'flex', alignItems: 'center',
  },
  controls: { display: 'flex', alignItems: 'center', gap: '10px' },
  filterInput: {
    padding: '6px 12px', borderRadius: '8px', fontSize: '12px',
    backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)',
    color: '#e2e8f0', width: '180px', fontFamily: '"JetBrains Mono", monospace',
  },
  controlBtn: {
    padding: '5px 14px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
    border: 'none', color: '#fff', cursor: 'pointer',
  },
  flowCount: {
    fontSize: '11px', color: '#64748b', padding: '4px 10px',
    background: 'rgba(0,0,0,0.2)', borderRadius: '8px',
  },
  tableHeader: {
    display: 'flex', padding: '8px 12px', background: 'rgba(0,0,0,0.3)',
    borderRadius: '8px 8px 0 0', borderBottom: '1px solid rgba(255,255,255,0.06)',
  },
  col: {
    fontSize: '10px', fontWeight: 600, color: '#475569',
    textTransform: 'uppercase' as const, letterSpacing: '0.5px',
    fontFamily: '"JetBrains Mono", monospace', overflow: 'hidden',
    textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const,
  },
  flowList: {
    maxHeight: '500px', overflowY: 'auto' as const,
    background: 'rgba(0,0,0,0.15)', borderRadius: '0 0 8px 8px',
  },
  flowRow: {
    display: 'flex', alignItems: 'center', padding: '6px 12px',
    borderLeft: '3px solid transparent', transition: 'background 0.2s',
    fontSize: '12px', fontFamily: '"JetBrains Mono", monospace',
  },
  ipText: { color: '#e2e8f0', fontSize: '12px' },
  portText: { color: '#475569', fontSize: '11px' },
  protoBadge: {
    padding: '1px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 600,
    background: 'rgba(99,102,241,0.1)', color: '#818cf8',
  },
  sevBadge: {
    padding: '1px 6px', borderRadius: '4px', fontSize: '9px', fontWeight: 700,
    border: '1px solid',
  },
  emptyState: {
    textAlign: 'center' as const, padding: '60px 20px', color: '#475569',
    fontSize: '13px',
  },
};

export default LiveFlowViewer;
