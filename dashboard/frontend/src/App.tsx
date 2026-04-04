import React, { useState, useEffect, useCallback } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Container, Box, Typography, Grid } from '@mui/material';
import AlertTable from './components/AlertTable';
import StatsCards from './components/StatsCards';
import SeverityChart from './components/SeverityChart';
import TimelineChart from './components/TimelineChart';
import TopSourcesChart from './components/TopSourcesChart';
import ThreatMap from './components/ThreatMap';
import NetworkTopology from './components/NetworkTopology';
import MitreHeatmap from './components/MitreHeatmap';
import LiveFlowViewer from './components/LiveFlowViewer';
import AlertInvestigation from './components/AlertInvestigation';
import LoginPage from './components/LoginPage';
import './styles/hacker.css';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#64ffda',
    },
    secondary: {
      main: '#536dfe',
    },
    background: {
      default: '#0a192f',
      paper: '#112240',
    },
    text: {
      primary: '#ccd6f6',
      secondary: '#8892b0',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
  },
});

type Page = 'dashboard' | 'alerts' | 'mitre' | 'flows' | 'topology';

interface Alert {
  alert_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  severity: string;
  threat_label: string;
  final_threat_score: number;
  confidence: number;
  reason: string;
}

interface Stats {
  total_alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unique_sources: number;
  unique_destinations: number;
  avg_threat_score: string;
  live_mode?: boolean;
  websocket_clients?: number;
}

const NAV_ITEMS: { id: Page; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
  { id: 'alerts', label: 'Alerts', icon: '🚨' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: '⬡' },
  { id: 'flows', label: 'Live Flows', icon: '📡' },
  { id: 'topology', label: 'Topology', icon: '🌐' },
];

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<Page>('dashboard');
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(() =>
    !!localStorage.getItem('sentinelhunt_token')
  );
  const [currentUser, setCurrentUser] = useState(() =>
    localStorage.getItem('sentinelhunt_user') || ''
  );

  const handleLogin = (token: string, username: string) => {
    setIsAuthenticated(true);
    setCurrentUser(username);
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinelhunt_token');
    localStorage.removeItem('sentinelhunt_user');
    setIsAuthenticated(false);
    setCurrentUser('');
  };

  const fetchData = useCallback(async () => {
    try {
      const alertsResponse = await fetch('http://localhost:5000/api/alerts');
      const statsResponse = await fetch('http://localhost:5000/api/stats');

      if (!alertsResponse.ok || !statsResponse.ok) {
        throw new Error(`Failed to fetch data: ${alertsResponse.status} ${statsResponse.status}`);
      }

      const alertsData = await alertsResponse.json();
      const statsData = await statsResponse.json();

      const alertsArray = alertsData.data || alertsData;
      setAlerts(Array.isArray(alertsArray) ? alertsArray : []);
      setStats(statsData);
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error('Fetch error:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
      setAlerts([]);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000); // Faster polling
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleAlertClick = (alertId: string) => {
    setSelectedAlertId(alertId);
  };

  const renderSidebar = () => (
    <div style={sidebarStyles.container}>
      <div style={sidebarStyles.logo}>
        <span style={sidebarStyles.logoIcon}>🛡</span>
        <div>
          <div style={sidebarStyles.logoText}>SentinelHunt</div>
          <div style={sidebarStyles.logoVersion}>v2.0 — Capstone</div>
        </div>
      </div>

      <nav style={sidebarStyles.nav}>
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            style={{
              ...sidebarStyles.navItem,
              ...(activePage === item.id ? sidebarStyles.navItemActive : {}),
            }}
            onClick={() => setActivePage(item.id)}
          >
            <span style={sidebarStyles.navIcon}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      {/* System Status */}
      <div style={sidebarStyles.statusSection}>
        <div style={sidebarStyles.statusTitle}>System Status</div>
        <div style={sidebarStyles.statusItem}>
          <span style={{ ...sidebarStyles.statusDot, backgroundColor: stats ? '#22c55e' : '#ef4444' }} />
          API Server
        </div>
        <div style={sidebarStyles.statusItem}>
          <span style={{ ...sidebarStyles.statusDot, backgroundColor: stats?.live_mode ? '#22c55e' : '#64748b' }} />
          Redis Streams
        </div>
        <div style={sidebarStyles.statusItem}>
          <span style={{ ...sidebarStyles.statusDot, backgroundColor: '#22c55e' }} />
          ML Engine
        </div>
        {stats && (
          <div style={sidebarStyles.statsBox}>
            <div style={sidebarStyles.statRow}>
              <span>Alerts</span>
              <span style={{ color: '#ef4444', fontWeight: 700 }}>{stats.total_alerts}</span>
            </div>
            <div style={sidebarStyles.statRow}>
              <span>Critical</span>
              <span style={{ color: '#ef4444', fontWeight: 700 }}>{stats.critical}</span>
            </div>
            <div style={sidebarStyles.statRow}>
              <span>Sources</span>
              <span style={{ fontWeight: 600 }}>{stats.unique_sources}</span>
            </div>
          </div>
        )}
      </div>

      {/* User & Logout */}
      <div style={{
        padding: '12px 16px',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ fontSize: '11px', color: '#94a3b8' }}>
          👤 {currentUser || 'analyst'}
        </div>
        <button
          onClick={handleLogout}
          style={{
            background: 'none',
            border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: '6px',
            color: '#ef4444',
            fontSize: '10px',
            padding: '4px 10px',
            cursor: 'pointer',
          }}
        >
          Logout
        </button>
      </div>
    </div>
  );

  const renderPageContent = () => {
    switch (activePage) {
      case 'dashboard':
        return (
          <>
            <StatsCards stats={stats || { total_alerts: 0, critical: 0, high: 0, medium: 0, low: 0, unique_sources: 0, unique_destinations: 0, avg_threat_score: '0' }} />
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Box className="hacker-card" sx={{ p: 2, height: 300 }}>
                  <SeverityChart />
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box className="hacker-card" sx={{ p: 2, height: 300 }}>
                  <TimelineChart />
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box className="hacker-card" sx={{ p: 2, height: 300 }}>
                  <TopSourcesChart />
                </Box>
              </Grid>
            </Grid>
            <Box className="hacker-card" sx={{ p: 2, mb: 3 }}>
              <MitreHeatmap />
            </Box>
            <Box className="hacker-card" sx={{ p: 2, mb: 3 }}>
              <ThreatMap alerts={alerts} />
            </Box>
          </>
        );

      case 'alerts':
        return (
          <Box className="hacker-card" sx={{ p: 2 }}>
            <AlertTable alerts={alerts} loading={loading} onAlertClick={handleAlertClick} />
          </Box>
        );

      case 'mitre':
        return (
          <Box className="hacker-card" sx={{ p: 2 }}>
            <MitreHeatmap />
          </Box>
        );

      case 'flows':
        return (
          <Box className="hacker-card" sx={{ p: 2 }}>
            <LiveFlowViewer />
          </Box>
        );

      case 'topology':
        return (
          <Box className="hacker-card" sx={{ p: 2 }}>
            <NetworkTopology alerts={alerts} />
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      {!isAuthenticated ? (
        <LoginPage onLogin={handleLogin} />
      ) : (
      <div style={{ display: 'flex', minHeight: '100vh' }}>
        {/* Sidebar */}
        {renderSidebar()}

        {/* Main Content */}
        <div style={{ flex: 1, marginLeft: '240px' }}>
          <Container
            maxWidth="xl"
            sx={{
              py: 3,
              px: { xs: 2, md: 3 },
            }}
          >
            {/* Page Title */}
            <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography
                variant="h5"
                sx={{
                  fontFamily: '"JetBrains Mono", monospace',
                  fontWeight: 700,
                  color: '#e2e8f0',
                }}
              >
                {NAV_ITEMS.find(n => n.id === activePage)?.icon}{' '}
                {NAV_ITEMS.find(n => n.id === activePage)?.label}
              </Typography>

              {error && (
                <Typography
                  sx={{
                    color: '#f97316',
                    fontSize: '12px',
                    fontFamily: '"JetBrains Mono", monospace',
                  }}
                >
                  ⚠ {error}
                </Typography>
              )}
            </Box>

            {renderPageContent()}
          </Container>
        </div>

        {/* Alert Investigation Modal */}
        {selectedAlertId && (
          <AlertInvestigation
            alertId={selectedAlertId}
            onClose={() => setSelectedAlertId(null)}
          />
        )}
      </div>
      )}
    </ThemeProvider>
  );
}

const sidebarStyles: Record<string, React.CSSProperties> = {
  container: {
    position: 'fixed',
    top: 0,
    left: 0,
    width: '240px',
    height: '100vh',
    backgroundColor: '#0c1222',
    borderRight: '1px solid rgba(99,102,241,0.15)',
    display: 'flex',
    flexDirection: 'column',
    zIndex: 100,
    overflowY: 'auto',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '20px 16px',
    borderBottom: '1px solid rgba(255,255,255,0.06)',
  },
  logoIcon: { fontSize: '28px' },
  logoText: {
    fontSize: '16px',
    fontWeight: 700,
    color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
  },
  logoVersion: {
    fontSize: '10px',
    color: '#64748b',
  },
  nav: {
    padding: '12px 8px',
    flex: 1,
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    width: '100%',
    padding: '10px 14px',
    marginBottom: '4px',
    borderRadius: '8px',
    border: 'none',
    background: 'transparent',
    color: '#94a3b8',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.2s',
    textAlign: 'left' as const,
    fontFamily: '"Inter", sans-serif',
  },
  navItemActive: {
    backgroundColor: 'rgba(99,102,241,0.15)',
    color: '#e2e8f0',
    fontWeight: 600,
    borderLeft: '3px solid #6366f1',
  },
  navIcon: { fontSize: '16px' },
  statusSection: {
    padding: '16px',
    borderTop: '1px solid rgba(255,255,255,0.06)',
  },
  statusTitle: {
    fontSize: '10px',
    fontWeight: 600,
    color: '#475569',
    textTransform: 'uppercase' as const,
    letterSpacing: '1px',
    marginBottom: '10px',
  },
  statusItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '11px',
    color: '#94a3b8',
    marginBottom: '6px',
  },
  statusDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
  },
  statsBox: {
    marginTop: '12px',
    padding: '10px',
    background: 'rgba(0,0,0,0.2)',
    borderRadius: '8px',
  },
  statRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '11px',
    color: '#94a3b8',
    marginBottom: '4px',
  },
};

export default App;
