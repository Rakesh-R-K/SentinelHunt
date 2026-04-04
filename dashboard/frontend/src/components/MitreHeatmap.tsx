import React, { useState, useEffect, useMemo } from 'react';

// ==========================================
// MITRE ATT&CK Heatmap Component
// ==========================================
// Displays an interactive MITRE ATT&CK matrix heatmap
// showing which techniques have been detected and their frequency.

interface Technique {
  id: string;
  name: string;
  count: number;
  alerts?: string[];
}

interface MitreData {
  total_techniques: number;
  techniques: Technique[];
}

// MITRE ATT&CK Enterprise Tactics (ordered)
const ATT_CK_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', color: '#6366f1' },
  { id: 'TA0042', name: 'Resource Development', color: '#8b5cf6' },
  { id: 'TA0001', name: 'Initial Access', color: '#a855f7' },
  { id: 'TA0002', name: 'Execution', color: '#d946ef' },
  { id: 'TA0003', name: 'Persistence', color: '#ec4899' },
  { id: 'TA0004', name: 'Privilege Escalation', color: '#f43f5e' },
  { id: 'TA0005', name: 'Defense Evasion', color: '#ef4444' },
  { id: 'TA0006', name: 'Credential Access', color: '#f97316' },
  { id: 'TA0007', name: 'Discovery', color: '#eab308' },
  { id: 'TA0008', name: 'Lateral Movement', color: '#84cc16' },
  { id: 'TA0009', name: 'Collection', color: '#22c55e' },
  { id: 'TA0011', name: 'Command & Control', color: '#14b8a6' },
  { id: 'TA0010', name: 'Exfiltration', color: '#06b6d4' },
  { id: 'TA0040', name: 'Impact', color: '#3b82f6' },
];

// Technique-to-Tactic mapping (subset relevant to SentinelHunt)
const TECHNIQUE_TACTIC_MAP: Record<string, string> = {
  'T1595': 'TA0043',
  'T1046': 'TA0043',
  'T1071.004': 'TA0011', 'T1071.001': 'TA0011',
  'T1568.002': 'TA0011',
  'T1573.002': 'TA0011',
  'T1571': 'TA0011', 'T1572': 'TA0011',
  'T1021': 'TA0008', 'T1021.001': 'TA0008',
  'T1021.002': 'TA0008', 'T1021.004': 'TA0008',
  'T1110': 'TA0006', 'T1110.001': 'TA0006',
  'T1110.003': 'TA0006', 'T1110.004': 'TA0006',
  'T1041': 'TA0010', 'T1048': 'TA0010', 'T1048.003': 'TA0010',
  'T1567': 'TA0010',
};

const MitreHeatmap: React.FC = () => {
  const [data, setData] = useState<MitreData | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch('http://localhost:5000/api/mitre/coverage');
        if (res.ok) {
          const json = await res.json();
          setData(json);
        }
      } catch (e) {
        console.error('Failed to fetch MITRE data:', e);
      }
      setLoading(false);
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const techniquesByTactic = useMemo(() => {
    if (!data) return {};
    const grouped: Record<string, Technique[]> = {};

    data.techniques.forEach(tech => {
      const tacticId = TECHNIQUE_TACTIC_MAP[tech.id] || 'TA0043';
      if (!grouped[tacticId]) grouped[tacticId] = [];
      grouped[tacticId].push(tech);
    });

    return grouped;
  }, [data]);

  const maxCount = useMemo(() => {
    if (!data) return 1;
    return Math.max(...data.techniques.map(t => t.count), 1);
  }, [data]);

  const getHeatColor = (count: number) => {
    if (count === 0) return 'rgba(255,255,255,0.03)';
    const intensity = Math.min(count / maxCount, 1);
    if (intensity > 0.7) return `rgba(239, 68, 68, ${0.3 + intensity * 0.7})`;
    if (intensity > 0.4) return `rgba(249, 115, 22, ${0.3 + intensity * 0.6})`;
    return `rgba(234, 179, 8, ${0.2 + intensity * 0.5})`;
  };

  if (loading) {
    return (
      <div style={styles.container}>
        <div style={styles.loading}>Loading MITRE ATT&CK data...</div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h2 style={styles.title}>
          <span style={{ color: '#ef4444' }}>⬡</span> MITRE ATT&CK Coverage
        </h2>
        <div style={styles.stats}>
          <span style={styles.statBadge}>
            {data?.total_techniques || 0} Techniques Detected
          </span>
          <span style={styles.statBadge}>
            {data?.techniques.reduce((s, t) => s + t.count, 0) || 0} Total Hits
          </span>
        </div>
      </div>

      <div style={styles.matrixContainer}>
        {ATT_CK_TACTICS.map(tactic => {
          const techs = techniquesByTactic[tactic.id] || [];
          return (
            <div key={tactic.id} style={styles.tacticColumn}>
              <div style={{ ...styles.tacticHeader, borderBottomColor: tactic.color }}>
                <span style={styles.tacticId}>{tactic.id}</span>
                <span style={styles.tacticName}>{tactic.name}</span>
                {techs.length > 0 && (
                  <span style={{ ...styles.tacticCount, backgroundColor: tactic.color }}>
                    {techs.length}
                  </span>
                )}
              </div>
              <div style={styles.techniqueList}>
                {techs.map(tech => (
                  <div
                    key={tech.id}
                    style={{
                      ...styles.techniqueCell,
                      backgroundColor: getHeatColor(tech.count),
                      borderColor: selectedTechnique?.id === tech.id ? '#fff' : 'transparent',
                    }}
                    onClick={() => setSelectedTechnique(tech)}
                    title={`${tech.name} — ${tech.count} detections`}
                  >
                    <span style={styles.techId}>{tech.id}</span>
                    <span style={styles.techName}>{tech.name}</span>
                    <span style={styles.techCount}>{tech.count}</span>
                  </div>
                ))}
                {techs.length === 0 && (
                  <div style={styles.emptyCell}>No detections</div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {selectedTechnique && (
        <div style={styles.detailPanel}>
          <div style={styles.detailHeader}>
            <h3 style={styles.detailTitle}>
              {selectedTechnique.id}: {selectedTechnique.name}
            </h3>
            <button style={styles.closeBtn} onClick={() => setSelectedTechnique(null)}>×</button>
          </div>
          <div style={styles.detailBody}>
            <div style={styles.detailStat}>
              <span style={styles.detailLabel}>Total Detections</span>
              <span style={styles.detailValue}>{selectedTechnique.count}</span>
            </div>
            {selectedTechnique.alerts && selectedTechnique.alerts.length > 0 && (
              <div style={styles.detailStat}>
                <span style={styles.detailLabel}>Related Alerts</span>
                <div style={styles.alertList}>
                  {selectedTechnique.alerts.map(id => (
                    <span key={id} style={styles.alertBadge}>{id}</span>
                  ))}
                </div>
              </div>
            )}
            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              style={styles.mitreLink}
            >
              View on MITRE ATT&CK →
            </a>
          </div>
        </div>
      )}

      <div style={styles.legend}>
        <span style={styles.legendLabel}>Detection Frequency:</span>
        <div style={{ ...styles.legendBox, backgroundColor: 'rgba(234,179,8,0.3)' }} /> Low
        <div style={{ ...styles.legendBox, backgroundColor: 'rgba(249,115,22,0.5)' }} /> Medium
        <div style={{ ...styles.legendBox, backgroundColor: 'rgba(239,68,68,0.8)' }} /> High
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: { padding: '24px 0' },
  loading: {
    textAlign: 'center', padding: '60px', color: '#94a3b8',
    fontSize: '14px', fontFamily: '"JetBrains Mono", monospace',
  },
  header: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    marginBottom: '24px', flexWrap: 'wrap', gap: '12px',
  },
  title: {
    margin: 0, fontSize: '20px', fontWeight: 700,
    fontFamily: '"JetBrains Mono", monospace', color: '#e2e8f0',
  },
  stats: { display: 'flex', gap: '8px' },
  statBadge: {
    padding: '4px 12px', borderRadius: '20px', fontSize: '12px',
    fontWeight: 600, background: 'rgba(239,68,68,0.15)', color: '#ef4444',
    border: '1px solid rgba(239,68,68,0.3)',
  },
  matrixContainer: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
    gap: '8px', marginBottom: '20px',
  },
  tacticColumn: {
    background: 'rgba(15,23,42,0.6)', borderRadius: '8px',
    border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden',
  },
  tacticHeader: {
    padding: '10px 12px', borderBottom: '2px solid',
    display: 'flex', flexDirection: 'column', gap: '2px',
  },
  tacticId: { fontSize: '10px', color: '#64748b', fontFamily: '"JetBrains Mono", monospace' },
  tacticName: { fontSize: '12px', fontWeight: 600, color: '#cbd5e1' },
  tacticCount: {
    alignSelf: 'flex-start', padding: '1px 8px', borderRadius: '10px',
    fontSize: '10px', fontWeight: 700, color: '#fff', marginTop: '4px',
  },
  techniqueList: { padding: '6px' },
  techniqueCell: {
    padding: '8px 10px', borderRadius: '6px', marginBottom: '4px',
    cursor: 'pointer', border: '1px solid transparent',
    transition: 'all 0.2s ease',
  },
  techId: {
    display: 'block', fontSize: '10px', color: '#94a3b8',
    fontFamily: '"JetBrains Mono", monospace',
  },
  techName: {
    display: 'block', fontSize: '11px', color: '#e2e8f0', fontWeight: 500,
    lineHeight: '1.3', marginTop: '2px',
  },
  techCount: {
    display: 'block', fontSize: '16px', fontWeight: 700, color: '#f97316',
    marginTop: '4px',
  },
  emptyCell: {
    padding: '16px', textAlign: 'center', fontSize: '11px', color: '#475569',
    fontStyle: 'italic',
  },
  detailPanel: {
    background: 'rgba(15,23,42,0.8)', borderRadius: '12px',
    border: '1px solid rgba(99,102,241,0.3)', padding: '20px',
    marginBottom: '20px', backdropFilter: 'blur(10px)',
  },
  detailHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  detailTitle: {
    margin: 0, fontSize: '16px', color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
  },
  closeBtn: {
    background: 'none', border: 'none', color: '#64748b', fontSize: '24px',
    cursor: 'pointer',
  },
  detailBody: { marginTop: '16px' },
  detailStat: { marginBottom: '12px' },
  detailLabel: { fontSize: '12px', color: '#64748b', display: 'block', marginBottom: '4px' },
  detailValue: { fontSize: '24px', fontWeight: 700, color: '#ef4444' },
  alertList: { display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' },
  alertBadge: {
    padding: '2px 10px', borderRadius: '12px', fontSize: '11px',
    background: 'rgba(99,102,241,0.15)', color: '#818cf8',
    border: '1px solid rgba(99,102,241,0.3)',
  },
  mitreLink: {
    display: 'inline-block', marginTop: '12px', color: '#60a5fa',
    fontSize: '13px', textDecoration: 'none',
  },
  legend: {
    display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px',
    color: '#64748b', paddingTop: '8px',
  },
  legendLabel: { fontWeight: 600 },
  legendBox: { width: '20px', height: '12px', borderRadius: '3px' },
};

export default MitreHeatmap;
