# SentinelHunt API Server

RESTful API backend for the SentinelHunt threat hunting dashboard.

## Features

- **Alert Management** - Query and filter security alerts
- **Incident Aggregation** - View correlated security incidents
- **Campaign Intelligence** - Track multi-stage attack campaigns
- **Flow Analytics** - Access network flow data with threat scores
- **Real-time Statistics** - System-wide security metrics
- **Chart Data** - Formatted endpoints for visualizations

## Installation

```bash
cd dashboard/backend

# Install dependencies
npm install

# Start development server with auto-reload
npm run dev

# Or start production server
npm start
```

## API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check and system status |
| GET | `/api/alerts` | Get all security alerts |
| GET | `/api/alerts/:id` | Get specific alert by ID |
| GET | `/api/incidents` | Get aggregated incidents |
| GET | `/api/campaigns` | Get detected attack campaigns |
| GET | `/api/timelines` | Get attack timeline data |
| GET | `/api/flows` | Get network flow data |
| GET | `/api/stats` | Get system-wide statistics |

### Chart Data Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/charts/severity` | Severity distribution |
| GET | `/api/charts/top-sources` | Top 10 attacking IPs |
| GET | `/api/charts/timeline` | Alert timeline by hour |

## Query Parameters

### `/api/alerts`

```
GET /api/alerts?severity=CRITICAL&limit=50&offset=0
```

- `severity` - Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `limit` - Maximum results to return
- `offset` - Pagination offset

### `/api/flows`

```
GET /api/flows?suspicious_only=true&limit=100
```

- `suspicious_only` - Only return flows with threat_score > 0.5
- `limit` - Maximum results to return

## Response Format

### Success Response

```json
{
  "total": 245,
  "offset": 0,
  "limit": 50,
  "data": [...]
}
```

### Error Response

```json
{
  "error": "Error description",
  "message": "Detailed error message"
}
```

## Example Usage

### Get Critical Alerts

```bash
curl http://localhost:5000/api/alerts?severity=CRITICAL
```

### Get System Statistics

```bash
curl http://localhost:5000/api/stats
```

### Get Top Attacking IPs

```bash
curl http://localhost:5000/api/charts/top-sources
```

## Data Sources

The API reads from the following data files:

```
../../feature_engineering/outputs/
├── alerts.json              # Raw alerts
├── aggregated_alerts.json   # Grouped incidents
├── campaigns.json           # Attack campaigns
├── timelines.json           # Timeline data
└── flow_threat_scores.csv   # Flow-level data
```

## Configuration

Environment variables (create `.env` file):

```env
PORT=5000
NODE_ENV=production
DATA_DIR=../../feature_engineering/outputs
```

## Performance

- **Caching**: Consider adding Redis for frequently accessed data
- **Compression**: Gzip enabled for all responses
- **Security**: Helmet.js for HTTP security headers
- **CORS**: Enabled for frontend access

## Development

### Hot Reload

```bash
npm run dev
```

### Testing

```bash
npm test
```

### Production Deployment

```bash
# Using PM2 process manager
npm install -g pm2
pm2 start server.js --name sentinelhunt-api
pm2 save
pm2 startup
```

## Integration

This API is designed to be consumed by:

1. **React Dashboard** - Web UI for analysts
2. **CLI Tools** - Command-line threat hunting
3. **SIEM Integration** - Export to Splunk/Elastic
4. **Custom Scripts** - Automated analysis

## Why Node.js?

- **JSON Native**: Natural fit for JSON-heavy security data
- **Non-Blocking I/O**: Handle concurrent analyst requests
- **NPM Ecosystem**: Rich middleware for security APIs
- **Industry Standard**: Used by major security platforms

## Future Enhancements

- [ ] WebSocket support for real-time alerts
- [ ] Authentication (JWT tokens)
- [ ] Rate limiting
- [ ] API versioning (v1, v2)
- [ ] Elasticsearch integration
- [ ] GraphQL endpoint

## License

Part of SentinelHunt - AI-Assisted Threat Hunting Platform
