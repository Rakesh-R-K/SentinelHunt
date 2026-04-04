import React, { useState } from 'react';

// ==========================================
// Login Page Component
// ==========================================
// Authentication gate for the SentinelHunt dashboard.
// Calls /api/auth/login and stores JWT in localStorage.

interface LoginPageProps {
  onLogin: (token: string, username: string) => void;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('sentinelhunt_token', data.token);
        localStorage.setItem('sentinelhunt_user', data.username);
        onLogin(data.token, data.username);
      } else {
        const data = await res.json();
        setError(data.error || 'Authentication failed');
      }
    } catch (err) {
      setError('Cannot connect to API server');
    }

    setLoading(false);
  };

  return (
    <div style={styles.container}>
      {/* Background animation */}
      <div style={styles.bgGrid} />

      <div style={styles.loginCard}>
        {/* Logo */}
        <div style={styles.logoSection}>
          <div style={styles.shieldIcon}>🛡</div>
          <h1 style={styles.title}>SentinelHunt</h1>
          <p style={styles.subtitle}>AI-Powered Threat Hunting Platform</p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Username</label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="analyst"
              style={styles.input}
              autoComplete="username"
              autoFocus
            />
          </div>

          <div style={styles.inputGroup}>
            <label style={styles.label}>Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••••••"
              style={styles.input}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div style={styles.errorBox}>
              <span style={styles.errorIcon}>⚠</span> {error}
            </div>
          )}

          <button
            id="login-submit"
            type="submit"
            style={{
              ...styles.submitBtn,
              opacity: loading ? 0.7 : 1,
            }}
            disabled={loading}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        {/* Demo credentials hint */}
        <div style={styles.demoHint}>
          <span style={styles.demoLabel}>Demo credentials:</span>
          <code style={styles.demoCode}>analyst / sentinelhunt2026</code>
        </div>

        {/* Version info */}
        <div style={styles.versionInfo}>
          SentinelHunt v2.0 — Capstone Edition
        </div>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'linear-gradient(135deg, #0a0f1c 0%, #0f172a 40%, #1a1040 100%)',
    position: 'relative',
    overflow: 'hidden',
  },
  bgGrid: {
    position: 'absolute',
    inset: 0,
    backgroundImage: `
      linear-gradient(rgba(99,102,241,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(99,102,241,0.03) 1px, transparent 1px)
    `,
    backgroundSize: '40px 40px',
    pointerEvents: 'none',
  },
  loginCard: {
    width: '380px',
    maxWidth: '90vw',
    background: 'rgba(15,23,42,0.8)',
    borderRadius: '20px',
    border: '1px solid rgba(99,102,241,0.2)',
    boxShadow: '0 40px 100px rgba(0,0,0,0.5), 0 0 60px rgba(99,102,241,0.1)',
    backdropFilter: 'blur(20px)',
    padding: '40px 32px',
    position: 'relative',
    zIndex: 1,
  },
  logoSection: {
    textAlign: 'center' as const,
    marginBottom: '32px',
  },
  shieldIcon: {
    fontSize: '48px',
    marginBottom: '12px',
    filter: 'drop-shadow(0 0 20px rgba(99,102,241,0.3))',
  },
  title: {
    margin: '0 0 4px',
    fontSize: '28px',
    fontWeight: 800,
    color: '#e2e8f0',
    fontFamily: '"JetBrains Mono", monospace',
    letterSpacing: '-0.5px',
  },
  subtitle: {
    margin: 0,
    fontSize: '12px',
    color: '#64748b',
    letterSpacing: '1px',
    textTransform: 'uppercase' as const,
  },
  form: {},
  inputGroup: {
    marginBottom: '18px',
  },
  label: {
    display: 'block',
    fontSize: '11px',
    fontWeight: 600,
    color: '#94a3b8',
    marginBottom: '6px',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  },
  input: {
    width: '100%',
    padding: '12px 16px',
    borderRadius: '10px',
    border: '1px solid rgba(99,102,241,0.2)',
    background: 'rgba(0,0,0,0.3)',
    color: '#e2e8f0',
    fontSize: '14px',
    fontFamily: '"JetBrains Mono", monospace',
    boxSizing: 'border-box' as const,
    outline: 'none',
    transition: 'border-color 0.2s, box-shadow 0.2s',
  },
  errorBox: {
    padding: '10px 14px',
    borderRadius: '8px',
    background: 'rgba(239,68,68,0.1)',
    border: '1px solid rgba(239,68,68,0.3)',
    color: '#ef4444',
    fontSize: '12px',
    marginBottom: '16px',
  },
  errorIcon: {
    marginRight: '6px',
  },
  submitBtn: {
    width: '100%',
    padding: '14px',
    borderRadius: '10px',
    border: 'none',
    background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
    color: '#fff',
    fontSize: '14px',
    fontWeight: 700,
    cursor: 'pointer',
    transition: 'transform 0.1s, box-shadow 0.2s',
    boxShadow: '0 4px 20px rgba(99,102,241,0.3)',
    letterSpacing: '0.5px',
  },
  demoHint: {
    marginTop: '24px',
    textAlign: 'center' as const,
    padding: '12px',
    borderRadius: '8px',
    background: 'rgba(99,102,241,0.05)',
    border: '1px dashed rgba(99,102,241,0.2)',
  },
  demoLabel: {
    fontSize: '10px',
    color: '#64748b',
    display: 'block',
    marginBottom: '4px',
    textTransform: 'uppercase' as const,
    letterSpacing: '1px',
  },
  demoCode: {
    fontSize: '13px',
    color: '#818cf8',
    fontFamily: '"JetBrains Mono", monospace',
  },
  versionInfo: {
    marginTop: '20px',
    textAlign: 'center' as const,
    fontSize: '10px',
    color: '#334155',
  },
};

export default LoginPage;
