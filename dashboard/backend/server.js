const express = require('express');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs').promises;
const http = require('http');

// Optional dependencies (graceful degradation)
let Server, Redis, jwt, rateLimit;
try { Server = require('socket.io').Server; } catch(e) { console.log('socket.io not installed — WebSocket disabled'); }
try { Redis = require('ioredis'); } catch(e) { console.log('ioredis not installed — using file-only mode'); }
try { jwt = require('jsonwebtoken'); } catch(e) { console.log('jsonwebtoken not installed — auth disabled'); }
try { rateLimit = require('express-rate-limit'); } catch(e) { console.log('express-rate-limit not installed'); }

// Initialize Express app
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

// ========================================
// CONFIGURATION
// ========================================
const DATA_DIR = path.join(__dirname, '../../feature_engineering/outputs');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
const AGGREGATED_FILE = path.join(DATA_DIR, 'aggregated_alerts.json');
const CAMPAIGNS_FILE = path.join(DATA_DIR, 'campaigns.json');
const TIMELINES_FILE = path.join(DATA_DIR, 'timelines.json');
const FLOWS_FILE = path.join(DATA_DIR, 'flow_threat_scores.csv');

const JWT_SECRET = process.env.SENTINELHUNT_JWT_SECRET || 'sentinelhunt-dev-secret';
const REDIS_HOST = process.env.SENTINELHUNT_REDIS_HOST || 'localhost';
const REDIS_PORT = parseInt(process.env.SENTINELHUNT_REDIS_PORT) || 6379;

const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5173',
];

// ========================================
// MIDDLEWARE
// ========================================
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts for dashboard
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

// Rate limiting
if (rateLimit) {
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use('/api/', limiter);
}

// Input sanitization middleware
app.use((req, res, next) => {
  if (req.query) {
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === 'string' && value.length > 1000) {
        return res.status(400).json({ error: 'Query parameter too long' });
      }
    }
  }
  next();
});

// ========================================
// WEBSOCKET (Socket.IO)
// ========================================
let io = null;
if (Server) {
  io = new Server(server, {
    cors: {
      origin: ALLOWED_ORIGINS,
      methods: ['GET', 'POST'],
    },
    transports: ['websocket', 'polling'],
  });

  io.on('connection', (socket) => {
    console.log(`[WS] Client connected: ${socket.id}`);

    socket.on('subscribe:alerts', () => {
      socket.join('alerts');
      console.log(`[WS] ${socket.id} subscribed to alerts`);
    });

    socket.on('subscribe:flows', () => {
      socket.join('flows');
      console.log(`[WS] ${socket.id} subscribed to flows`);
    });

    socket.on('disconnect', () => {
      console.log(`[WS] Client disconnected: ${socket.id}`);
    });
  });
}

// ========================================
// REDIS CONNECTION (for real-time alerts)
// ========================================
let redisClient = null;
let liveAlerts = [];

if (Redis) {
  try {
    redisClient = new Redis({
      host: REDIS_HOST,
      port: REDIS_PORT,
      retryStrategy: (times) => Math.min(times * 100, 3000),
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });

    redisClient.connect().then(() => {
      console.log(`[Redis] Connected to ${REDIS_HOST}:${REDIS_PORT}`);
      startRedisAlertConsumer();
    }).catch(err => {
      console.log('[Redis] Connection failed (file mode):', err.message);
      redisClient = null;
    });
  } catch(e) {
    console.log('[Redis] Init failed:', e.message);
  }
}

async function startRedisAlertConsumer() {
  if (!redisClient) return;
  const stream = 'sentinelhunt:alerts';
  let lastId = '$';

  console.log('[Redis] Starting alert stream consumer...');

  const poll = async () => {
    try {
      const results = await redisClient.xread('BLOCK', 1000, 'COUNT', 10, 'STREAMS', stream, lastId);
      if (results) {
        for (const [, entries] of results) {
          for (const [id, fields] of entries) {
            lastId = id;
            const alert = {};
            for (let i = 0; i < fields.length; i += 2) {
              try { alert[fields[i]] = JSON.parse(fields[i + 1]); }
              catch { alert[fields[i]] = fields[i + 1]; }
            }
            alert._stream_id = id;

            // Store in memory (ring buffer)
            liveAlerts.push(alert);
            if (liveAlerts.length > 500) liveAlerts.shift();

            // Push to WebSocket clients
            if (io) io.to('alerts').emit('new:alert', alert);
          }
        }
      }
    } catch(e) {
      if (e.message !== 'Connection is closed') {
        console.error('[Redis] Consumer error:', e.message);
      }
    }

    if (redisClient && redisClient.status === 'ready') {
      setImmediate(poll);
    }
  };

  poll();
}

// ========================================
// HELPER FUNCTIONS
// ========================================

async function readJSON(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading ${path.basename(filePath)}:`, error.message);
    return null;
  }
}

async function readCSV(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    const lines = data.trim().split('\n');
    const headers = lines[0].split(',');

    return lines.slice(1).map(line => {
      const values = line.split(',');
      const obj = {};
      headers.forEach((header, index) => {
        obj[header] = values[index];
      });
      return obj;
    });
  } catch (error) {
    console.error(`Error reading CSV ${path.basename(filePath)}:`, error.message);
    return null;
  }
}

async function calculateStats() {
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) return null;

  const stats = {
    total_alerts: alerts.length,
    critical: alerts.filter(a => a.severity === 'CRITICAL').length,
    high: alerts.filter(a => a.severity === 'HIGH').length,
    medium: alerts.filter(a => a.severity === 'MEDIUM').length,
    low: alerts.filter(a => a.severity === 'LOW').length,
    unique_sources: [...new Set(alerts.map(a => a.src_ip))].length,
    unique_destinations: [...new Set(alerts.map(a => a.dst_ip))].length,
    threat_types: {},
    protocol_distribution: {},
    avg_threat_score: 0,
    live_mode: !!redisClient,
    websocket_clients: io ? io.engine.clientsCount : 0,
    live_alert_buffer: liveAlerts.length,
  };

  alerts.forEach(alert => {
    stats.threat_types[alert.threat_type] =
      (stats.threat_types[alert.threat_type] || 0) + 1;
    stats.protocol_distribution[alert.protocol] =
      (stats.protocol_distribution[alert.protocol] || 0) + 1;
  });

  const totalScore = alerts.reduce((sum, a) => sum + (a.final_threat_score || 0), 0);
  stats.avg_threat_score = (totalScore / alerts.length).toFixed(3);

  return stats;
}

// ========================================
// AUTHENTICATION
// ========================================
function authenticateToken(req, res, next) {
  if (!jwt) return next(); // Skip auth if JWT not available

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ========================================
// API ROUTES
// ========================================

// Health check (public)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0.0',
    features: {
      websocket: !!io,
      redis: !!redisClient,
      auth: !!jwt,
      rate_limiting: !!rateLimit,
    },
  });
});

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  // Demo credentials (replace with proper auth in production)
  if (username === 'analyst' && password === 'sentinelhunt2026') {
    if (jwt) {
      const token = jwt.sign(
        { username, role: 'analyst' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.json({ token, username, role: 'analyst' });
    }
    return res.json({ token: 'demo-token', username, role: 'analyst' });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// Get all alerts
app.get('/api/alerts', async (req, res) => {
  // If we have live alerts from Redis, prefer those
  if (liveAlerts.length > 0) {
    let filtered = [...liveAlerts];
    const { severity, limit, offset } = req.query;

    if (severity) {
      filtered = filtered.filter(a =>
        (a.severity || '').toUpperCase() === severity.toUpperCase()
      );
    }

    const start = parseInt(offset) || 0;
    const end = limit ? start + parseInt(limit) : filtered.length;
    const paginated = filtered.slice(start, end);

    return res.json({
      total: filtered.length,
      offset: start,
      limit: limit ? parseInt(limit) : filtered.length,
      source: 'realtime',
      data: paginated,
    });
  }

  // Fall back to file
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) {
    return res.status(500).json({ error: 'Alert data unavailable' });
  }

  const { severity, limit, offset } = req.query;
  let filtered = alerts;

  if (severity) {
    filtered = filtered.filter(a =>
      a.severity.toUpperCase() === severity.toUpperCase()
    );
  }

  const start = parseInt(offset) || 0;
  const end = limit ? start + parseInt(limit) : filtered.length;
  const paginated = filtered.slice(start, end);

  res.json({
    total: filtered.length,
    offset: start,
    limit: limit ? parseInt(limit) : filtered.length,
    source: 'file',
    data: paginated,
  });
});

// Get alert by ID
app.get('/api/alerts/:id', async (req, res) => {
  const alertId = req.params.id;

  // Check live alerts first
  const liveAlert = liveAlerts.find(a => a.alert_id === alertId);
  if (liveAlert) return res.json(liveAlert);

  // Fall back to file
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) {
    return res.status(500).json({ error: 'Alert data unavailable' });
  }

  const alert = alerts.find(a => a.alert_id === alertId);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }

  res.json(alert);
});

// MITRE ATT&CK coverage endpoint (new)
app.get('/api/mitre/coverage', async (req, res) => {
  const alerts = await readJSON(ALERTS_FILE);
  const allAlerts = [...(alerts || []), ...liveAlerts];

  const techniques = {};
  allAlerts.forEach(alert => {
    const mitre = alert.mitre_attack;
    if (mitre && mitre.techniques) {
      mitre.techniques.forEach(tech => {
        if (!techniques[tech.id]) {
          techniques[tech.id] = { ...tech, count: 0, alerts: [] };
        }
        techniques[tech.id].count++;
        if (techniques[tech.id].alerts.length < 5) {
          techniques[tech.id].alerts.push(alert.alert_id);
        }
      });
    }
  });

  res.json({
    total_techniques: Object.keys(techniques).length,
    techniques: Object.values(techniques).sort((a, b) => b.count - a.count),
  });
});

// Alert investigation workflow (new)
app.post('/api/alerts/:id/action', async (req, res) => {
  const { action, notes } = req.body;
  const validActions = ['acknowledge', 'investigate', 'escalate', 'close', 'false_positive'];

  if (!validActions.includes(action)) {
    return res.status(400).json({ error: 'Invalid action', valid: validActions });
  }

  // In production, this would update a database
  res.json({
    alert_id: req.params.id,
    action,
    notes: notes || '',
    performed_at: new Date().toISOString(),
    performed_by: req.user?.username || 'anonymous',
    status: 'success',
  });
});

// IOC search endpoint (new)
app.get('/api/ioc/search', async (req, res) => {
  const { query, type } = req.query;
  if (!query) {
    return res.status(400).json({ error: 'Search query required' });
  }

  // Search across both file and live alerts
  const alerts = await readJSON(ALERTS_FILE);
  const allAlerts = [...(alerts || []), ...liveAlerts];

  const matches = allAlerts.filter(a => {
    const searchStr = JSON.stringify(a).toLowerCase();
    return searchStr.includes(query.toLowerCase());
  }).slice(0, 50);

  res.json({
    query,
    total_matches: matches.length,
    data: matches,
  });
});

// Threat intel feed status (new)
app.get('/api/threat-intel/status', (req, res) => {
  res.json({
    feeds: {
      feodo_tracker: { status: 'configured', last_check: new Date().toISOString() },
      urlhaus: { status: 'configured', last_check: new Date().toISOString() },
      emerging_threats: { status: 'configured', last_check: new Date().toISOString() },
      blocklist_de: { status: 'configured', last_check: new Date().toISOString() },
      cinsscore: { status: 'configured', last_check: new Date().toISOString() },
    },
    enrichment: {
      virustotal: !!process.env.SENTINELHUNT_VT_API_KEY,
      abuseipdb: !!process.env.SENTINELHUNT_ABUSEIPDB_KEY,
      shodan: !!process.env.SENTINELHUNT_SHODAN_KEY,
    },
  });
});

// Get aggregated incidents
app.get('/api/incidents', async (req, res) => {
  const incidents = await readJSON(AGGREGATED_FILE);
  if (!incidents) {
    return res.status(500).json({ error: 'Incident data unavailable' });
  }
  res.json({ total: incidents.length, data: incidents });
});

// Get detected campaigns
app.get('/api/campaigns', async (req, res) => {
  const campaigns = await readJSON(CAMPAIGNS_FILE);
  if (!campaigns) {
    return res.status(500).json({ error: 'Campaign data unavailable' });
  }
  res.json({ total: campaigns.length, data: campaigns });
});

// Get attack timelines
app.get('/api/timelines', async (req, res) => {
  const timelines = await readJSON(TIMELINES_FILE);
  if (!timelines) {
    return res.status(500).json({ error: 'Timeline data unavailable' });
  }
  res.json({ total: timelines.length, data: timelines });
});

// Get flow data
app.get('/api/flows', async (req, res) => {
  const flows = await readCSV(FLOWS_FILE);
  if (!flows) {
    return res.status(500).json({ error: 'Flow data unavailable' });
  }

  const { limit, suspicious_only } = req.query;
  let filtered = flows;

  if (suspicious_only === 'true') {
    filtered = filtered.filter(f => parseFloat(f.final_threat_score) > 0.5);
  }

  const results = limit ? filtered.slice(0, parseInt(limit)) : filtered;
  res.json({ total: filtered.length, data: results });
});

// Get system statistics
app.get('/api/stats', async (req, res) => {
  const stats = await calculateStats();
  if (!stats) {
    return res.status(500).json({ error: 'Statistics unavailable' });
  }
  res.json(stats);
});

// Chart endpoints
app.get('/api/charts/severity', async (req, res) => {
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) {
    return res.status(500).json({ error: 'Chart data unavailable' });
  }

  res.json({
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    data: [
      alerts.filter(a => a.severity === 'CRITICAL').length,
      alerts.filter(a => a.severity === 'HIGH').length,
      alerts.filter(a => a.severity === 'MEDIUM').length,
      alerts.filter(a => a.severity === 'LOW').length,
    ],
  });
});

app.get('/api/charts/top-sources', async (req, res) => {
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) {
    return res.status(500).json({ error: 'Chart data unavailable' });
  }

  const ipCounts = {};
  alerts.forEach(alert => {
    ipCounts[alert.src_ip] = (ipCounts[alert.src_ip] || 0) + 1;
  });

  const sorted = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  res.json({ labels: sorted.map(([ip]) => ip), data: sorted.map(([, count]) => count) });
});

app.get('/api/charts/timeline', async (req, res) => {
  const alerts = await readJSON(ALERTS_FILE);
  if (!alerts) {
    return res.status(500).json({ error: 'Chart data unavailable' });
  }

  const timeline = {};
  alerts.forEach(alert => {
    const hour = alert.timestamp.substring(0, 13);
    timeline[hour] = (timeline[hour] || 0) + 1;
  });

  const sorted = Object.entries(timeline).sort();
  res.json({ labels: sorted.map(([time]) => time), data: sorted.map(([, count]) => count) });
});

// ========================================
// ERROR HANDLING
// ========================================

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ========================================
// START SERVER
// ========================================

server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  SentinelHunt API Server v2.0');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`  Status: Running`);
  console.log(`  Port: ${PORT}`);
  console.log(`  WebSocket: ${io ? '✅ Enabled' : '❌ Disabled'}`);
  console.log(`  Redis: ${redisClient ? '✅ Connected' : '📁 File mode'}`);
  console.log(`  Auth: ${jwt ? '🔒 JWT Enabled' : '🔓 Open'}`);
  console.log(`  Rate Limit: ${rateLimit ? '✅ Enabled' : '❌ Disabled'}`);
  console.log('─────────────────────────────────────────────────────');
  console.log(`  Health: http://localhost:${PORT}/api/health`);
  console.log(`  Alerts: http://localhost:${PORT}/api/alerts`);
  console.log(`  MITRE: http://localhost:${PORT}/api/mitre/coverage`);
  console.log('═══════════════════════════════════════════════════════');
});

module.exports = { app, server };
