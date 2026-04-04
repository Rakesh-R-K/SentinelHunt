import React, { useState, useEffect, useRef } from 'react';

// ==========================================
// Alert Investigation Panel Component
// ==========================================
// Full alert detail view with investigation workflow,
// MITRE mapping, threat intel enrichment, and analyst actions.

interface AlertDetail {
  alert_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  severity: string;
  final_threat_score: number;
  ml_score?: number;
  rule_score?: number;
  confidence?: number;
  threat_label: string;
  triggered_rules?: string[];
  indicators?: string[];
  mitre_attack?: {
    tactics: string[];
    techniques: { id: string; name: string }[];
  };
  investigation_guidance?: string[];
  flow_metadata?: {
    packet_count: number;
    total_bytes: number;
    duration: number;
  };
  threat_intel?: {
    source?: { risk_score: number; overall_risk: string };
    destination?: { risk_score: number; overall_risk: string };
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const ACTIONS = [
  { id: 'acknowledge', label: 'Acknowledge', icon: '👁', color: '#3b82f6' },
  { id: 'investigate', label: 'Investigate', icon: '🔍', color: '#8b5cf6' },
  { id: 'escalate', label: 'Escalate', icon: '⬆️', color: '#ef4444' },
  { id: 'close', label: 'Close', icon: '✅', color: '#22c55e' },
  { id: 'false_positive', label: 'False Positive', icon: '🚫', color: '#64748b' },
];

interface Props {
  alertId: string;
  onClose: () => void;
}

const AlertInvestigation: React.FC<Props> = ({ alertId, onClose }) => {
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'details' | 'mitre' | 'intel' | 'timeline'>('details');
  const [notes, setNotes] = useState('');
  const [actionHistory, setActionHistory] = useState<Array<{ action: string; time: string }>>([]);

  useEffect(() => {
    const fetchAlert = async () => {
      try {
        const res = await fetch(`http://localhost:5000/api/alerts/${alertId}`);
        if (res.ok) {
          const data = await res.json();
          setAlert(data);
        }
      } catch (e) {
        console.error('Failed to fetch alert:', e);
      }
      setLoading(false);
    };
    fetchAlert();
  }, [alertId]);

  const handleAction = async (action: string) => {
    try {
      await fetch(`http://localhost:5000/api/alerts/${alertId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, notes }),
      });
      setActionHistory(prev => [...prev, {
        action,
        time: new Date().toLocaleTimeString(),
      }]);
    } catch (e) {
      console.error('Action failed:', e);
    }
  };

  if (loading) {
    return (
      <div style={styles.overlay}>
        <div style={styles.panel}>
          <div style={styles.loading}>Loading alert data...</div>
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div style={styles.overlay}>
        <div style={styles.panel}>
          <div style={styles.loading}>Alert not found</div>
          <button style={styles.closeTopBtn} onClick={onClose}>×</button>
        </div>
      </div>
    );
  }

  const sevColor = SEVERITY_COLORS[alert.severity] || '#64748b';

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.panel} onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <div style={styles.alertIdRow}>
              <span style={{ ...styles.severityBadge, backgroundColor: sevColor }}>
                {alert.severity}
              </span>
              <span style={styles.alertIdText}>{alert.alert_id}</span>
            </div>
            <h2 style={styles.threatLabel}>{alert.threat_label}</h2>
            <span style={styles.timestamp}>{new Date(alert.timestamp).toLocaleString()}</span>
          </div>
          <button style={styles.closeTopBtn} onClick={onClose}>×</button>
        </div>

        {/* Score Gauges */}
        <div style={styles.scoreRow}>
          <ScoreGauge label="Threat Score" value={alert.final_threat_score} color={sevColor} />
          <ScoreGauge label="ML Score" value={alert.ml_score || 0} color="#8b5cf6" />
          <ScoreGauge label="Rule Score" value={alert.rule_score || 0} color="#3b82f6" />
          <ScoreGauge label="Confidence" value={alert.confidence || 0} color="#14b8a6" />
        </div>

        {/* Tabs */}
        <div style={styles.tabs}>
          {(['details', 'mitre', 'intel', 'timeline'] as const).map(tab => (
            <button
              key={tab}
              style={{
                ...styles.tab,
                ...(activeTab === tab ? styles.tabActive : {}),
              }}
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div style={styles.tabContent}>
          {activeTab === 'details' && (
            <div>
              {/* Connection Info */}
              <div style={styles.section}>
                <h4 style={styles.sectionTitle}>Connection</h4>
                <div style={styles.connectionFlow}>
                  <div style={styles.endpoint}>
                    <span style={styles.endpointLabel}>Source</span>
                    <span style={styles.ipAddress}>{alert.src_ip}</span>
                    <span style={styles.port}>:{alert.src_port}</span>
                  </div>
                  <span style={styles.arrow}>→</span>
                  <div style={styles.endpoint}>
                    <span style={styles.endpointLabel}>Destination</span>
                    <span style={styles.ipAddress}>{alert.dst_ip}</span>
                    <span style={styles.port}>:{alert.dst_port}</span>
                  </div>
                  <span style={styles.protocolBadge}>{alert.protocol}</span>
                </div>
              </div>

              {/* Triggered Rules */}
              {alert.triggered_rules && alert.triggered_rules.length > 0 && (
                <div style={styles.section}>
                  <h4 style={styles.sectionTitle}>Triggered Rules</h4>
                  <div style={styles.ruleList}>
                    {alert.triggered_rules.map(rule => (
                      <span key={rule} style={styles.ruleBadge}>{rule}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Indicators */}
              {alert.indicators && alert.indicators.length > 0 && (
                <div style={styles.section}>
                  <h4 style={styles.sectionTitle}>Detection Indicators</h4>
                  {alert.indicators.map((ind, i) => (
                    <div key={i} style={styles.indicator}>
                      <span style={styles.indicatorIcon}>⚠</span> {ind}
                    </div>
                  ))}
                </div>
              )}

              {/* Flow Metadata */}
              {alert.flow_metadata && (
                <div style={styles.section}>
                  <h4 style={styles.sectionTitle}>Flow Metadata</h4>
                  <div style={styles.metaGrid}>
                    <MetaItem label="Packets" value={String(alert.flow_metadata.packet_count)} />
                    <MetaItem label="Bytes" value={formatBytes(alert.flow_metadata.total_bytes)} />
                    <MetaItem label="Duration" value={`${alert.flow_metadata.duration.toFixed(2)}s`} />
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'mitre' && (
            <div>
              {alert.mitre_attack ? (
                <>
                  <div style={styles.section}>
                    <h4 style={styles.sectionTitle}>Mapped Tactics</h4>
                    <div style={styles.ruleList}>
                      {alert.mitre_attack.tactics.map(t => (
                        <span key={t} style={styles.mitreBadge}>{t}</span>
                      ))}
                    </div>
                  </div>
                  <div style={styles.section}>
                    <h4 style={styles.sectionTitle}>Mapped Techniques</h4>
                    {alert.mitre_attack.techniques.map(tech => (
                      <div key={tech.id} style={styles.techniqueRow}>
                        <span style={styles.techId}>{tech.id}</span>
                        <span style={styles.techName}>{tech.name}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={styles.techLink}
                        >↗</a>
                      </div>
                    ))}
                  </div>
                  {alert.investigation_guidance && (
                    <div style={styles.section}>
                      <h4 style={styles.sectionTitle}>Investigation Guidance</h4>
                      <ol style={styles.guidanceList}>
                        {alert.investigation_guidance.map((g, i) => (
                          <li key={i} style={styles.guidanceItem}>{g}</li>
                        ))}
                      </ol>
                    </div>
                  )}
                </>
              ) : (
                <div style={styles.emptyState}>No MITRE ATT&CK mapping available</div>
              )}
            </div>
          )}

          {activeTab === 'intel' && (
            <div>
              <div style={styles.emptyState}>
                🔍 Threat intelligence enrichment requires API keys.<br />
                Configure SENTINELHUNT_VT_API_KEY and SENTINELHUNT_ABUSEIPDB_KEY to enable.
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div>
              <div style={styles.section}>
                <h4 style={styles.sectionTitle}>Investigation Actions</h4>
                {actionHistory.length > 0 ? (
                  actionHistory.map((ah, i) => (
                    <div key={i} style={styles.timelineEntry}>
                      <span style={styles.timelineDot} />
                      <span style={styles.timelineAction}>{ah.action}</span>
                      <span style={styles.timelineTime}>{ah.time}</span>
                    </div>
                  ))
                ) : (
                  <div style={styles.emptyState}>No actions taken yet</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Action Bar */}
        <div style={styles.actionBar}>
          <div style={styles.actionsRow}>
            {ACTIONS.map(action => (
              <button
                key={action.id}
                style={{ ...styles.actionBtn, borderColor: action.color }}
                onClick={() => handleAction(action.id)}
              >
                {action.icon} {action.label}
              </button>
            ))}
          </div>
          <textarea
            style={styles.notesInput}
            placeholder="Analyst notes..."
            value={notes}
            onChange={e => setNotes(e.target.value)}
            rows={2}
          />
        </div>
      </div>
    </div>
  );
};

// Score Gauge sub-component
const ScoreGauge: React.FC<{ label: string; value: number; color: string }> = ({
  label, value, color,
}) => (
  <div style={styles.gauge}>
    <div style={styles.gaugeLabel}>{label}</div>
    <div style={styles.gaugeBar}>
      <div style={{
        ...styles.gaugeFill,
        width: `${Math.min(value * 100, 100)}%`,
        backgroundColor: color,
      }} />
    </div>
    <div style={{ ...styles.gaugeValue, color }}>{(value * 100).toFixed(1)}%</div>
  </div>
);

// Meta item sub-component
const MetaItem: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div style={styles.metaItem}>
    <span style={styles.metaLabel}>{label}</span>
    <span style={styles.metaValue}>{value}</span>
  </div>
);

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.7)',
    backdropFilter: 'blur(4px)', zIndex: 1000, display: 'flex',
    justifyContent: 'center', alignItems: 'flex-start', paddingTop: '40px',
    overflowY: 'auto',
  },
  panel: {
    width: '720px', maxWidth: '95vw', background: 'linear-gradient(145deg, #0f172a 0%, #1e293b 100%)',
    borderRadius: '16px', border: '1px solid rgba(99,102,241,0.2)',
    boxShadow: '0 25px 80px rgba(0,0,0,0.6)', marginBottom: '40px',
  },
  loading: {
    padding: '60px', textAlign: 'center', color: '#94a3b8',
    fontFamily: '"JetBrains Mono", monospace',
  },
  header: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
    padding: '24px 24px 16px',
  },
  alertIdRow: { display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' },
  severityBadge: {
    padding: '3px 12px', borderRadius: '12px', fontSize: '11px',
    fontWeight: 700, color: '#fff', textTransform: 'uppercase' as const,
  },
  alertIdText: {
    fontSize: '13px', color: '#64748b',
    fontFamily: '"JetBrains Mono", monospace',
  },
  threatLabel: {
    margin: 0, fontSize: '18px', fontWeight: 700, color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
  },
  timestamp: { fontSize: '12px', color: '#475569' },
  closeTopBtn: {
    background: 'none', border: 'none', color: '#64748b',
    fontSize: '28px', cursor: 'pointer', padding: '0 4px', lineHeight: 1,
  },
  scoreRow: {
    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px',
    padding: '0 24px 16px',
  },
  gauge: { textAlign: 'center' as const },
  gaugeLabel: { fontSize: '10px', color: '#64748b', marginBottom: '4px', textTransform: 'uppercase' as const },
  gaugeBar: {
    height: '6px', backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: '3px',
    overflow: 'hidden',
  },
  gaugeFill: { height: '100%', borderRadius: '3px', transition: 'width 0.5s ease' },
  gaugeValue: { fontSize: '14px', fontWeight: 700, marginTop: '4px' },
  tabs: {
    display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)',
    padding: '0 24px',
  },
  tab: {
    background: 'none', border: 'none', color: '#64748b', padding: '10px 16px',
    fontSize: '13px', cursor: 'pointer', fontWeight: 500,
    borderBottom: '2px solid transparent', transition: 'all 0.2s',
  },
  tabActive: { color: '#e2e8f0', borderBottomColor: '#6366f1' },
  tabContent: { padding: '20px 24px', minHeight: '200px', maxHeight: '400px', overflowY: 'auto' as const },
  section: { marginBottom: '20px' },
  sectionTitle: {
    fontSize: '12px', fontWeight: 600, color: '#94a3b8',
    textTransform: 'uppercase' as const, margin: '0 0 10px',
    letterSpacing: '0.5px',
  },
  connectionFlow: {
    display: 'flex', alignItems: 'center', gap: '12px',
    padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px',
  },
  endpoint: { display: 'flex', flexDirection: 'column' as const },
  endpointLabel: { fontSize: '10px', color: '#64748b' },
  ipAddress: {
    fontSize: '14px', fontWeight: 600, color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
  },
  port: { fontSize: '12px', color: '#64748b', fontFamily: '"JetBrains Mono", monospace' },
  arrow: { fontSize: '20px', color: '#ef4444' },
  protocolBadge: {
    padding: '3px 10px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
    background: 'rgba(99,102,241,0.15)', color: '#818cf8', marginLeft: 'auto',
  },
  ruleList: { display: 'flex', flexWrap: 'wrap' as const, gap: '6px' },
  ruleBadge: {
    padding: '4px 12px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
    background: 'rgba(239,68,68,0.1)', color: '#ef4444',
    border: '1px solid rgba(239,68,68,0.2)',
  },
  mitreBadge: {
    padding: '4px 12px', borderRadius: '8px', fontSize: '11px', fontWeight: 600,
    background: 'rgba(99,102,241,0.1)', color: '#818cf8',
    border: '1px solid rgba(99,102,241,0.2)',
  },
  indicator: {
    padding: '8px 12px', background: 'rgba(249,115,22,0.06)',
    borderRadius: '6px', fontSize: '12px', color: '#cbd5e1',
    marginBottom: '6px', lineHeight: '1.5',
  },
  indicatorIcon: { color: '#f97316', marginRight: '8px' },
  metaGrid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' },
  metaItem: {
    padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px',
    textAlign: 'center' as const,
  },
  metaLabel: { display: 'block', fontSize: '10px', color: '#64748b', marginBottom: '4px' },
  metaValue: {
    fontSize: '16px', fontWeight: 700, color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
  },
  techniqueRow: {
    display: 'flex', gap: '12px', alignItems: 'center',
    padding: '8px 12px', background: 'rgba(0,0,0,0.15)', borderRadius: '6px',
    marginBottom: '4px',
  },
  techId: {
    fontSize: '12px', color: '#818cf8', fontWeight: 600,
    fontFamily: '"JetBrains Mono", monospace', minWidth: '90px',
  },
  techName: { fontSize: '12px', color: '#cbd5e1', flex: 1 },
  techLink: { color: '#60a5fa', textDecoration: 'none', fontSize: '14px' },
  guidanceList: { paddingLeft: '20px', margin: 0 },
  guidanceItem: {
    fontSize: '12px', color: '#cbd5e1', marginBottom: '8px', lineHeight: '1.5',
  },
  emptyState: {
    textAlign: 'center' as const, padding: '40px 20px', color: '#475569',
    fontSize: '13px', lineHeight: '1.6',
  },
  timelineEntry: {
    display: 'flex', alignItems: 'center', gap: '12px',
    padding: '8px 0', borderLeft: '2px solid rgba(99,102,241,0.3)',
    paddingLeft: '16px', marginLeft: '8px',
  },
  timelineDot: {
    width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#6366f1',
    flexShrink: 0,
  },
  timelineAction: { fontSize: '13px', color: '#e2e8f0', fontWeight: 500, textTransform: 'capitalize' as const },
  timelineTime: { fontSize: '11px', color: '#475569', marginLeft: 'auto' },
  actionBar: {
    padding: '16px 24px', borderTop: '1px solid rgba(255,255,255,0.06)',
  },
  actionsRow: { display: 'flex', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' as const },
  actionBtn: {
    padding: '6px 14px', borderRadius: '8px', fontSize: '12px', fontWeight: 500,
    background: 'rgba(0,0,0,0.3)', border: '1px solid', color: '#e2e8f0',
    cursor: 'pointer', transition: 'all 0.2s',
  },
  notesInput: {
    width: '100%', padding: '10px 12px', borderRadius: '8px', fontSize: '12px',
    backgroundColor: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)',
    color: '#e2e8f0', resize: 'vertical' as const, boxSizing: 'border-box' as const,
    fontFamily: '"JetBrains Mono", monospace',
  },
};

export default AlertInvestigation;
