# 🔧 SentinelHunt Development Guide

Complete guide for developers, contributors, security researchers, and testers.

---

## 🚀 Quick Setup

### Prerequisites
```bash
# System dependencies
sudo apt install python3 python3-pip tcpdump golang nodejs npm

# Python
pip3 install -r requirements.txt

# Go
cd collector && go mod download

# Node.js
cd dashboard/backend && npm install
cd ../frontend && npm install
```

### Running the Platform
```bash
# Terminal 1: API
cd dashboard/backend && npm start

# Terminal 2: Dashboard  
cd dashboard/frontend && npm start

# Terminal 3: Collector (optional)
cd collector && sudo ./collector

# Access: http://localhost:3000
```

---

## 🧪 Testing

### Python Tests
```bash
pytest tests/ --cov=feature_engineering --cov=detection_engine
```

### Go Tests
```bash
cd collector && go test -v -cover
```

### Node.js Tests
```bash
cd dashboard/backend && npm test
```

---

## 🔒 Security

### Reporting Vulnerabilities
**DO NOT** open public issues. Email maintainers privately.

### Production Checklist
- [ ] Enable JWT authentication
- [ ] Configure HTTPS/TLS
- [ ] Set up rate limiting
- [ ] Enable security headers
- [ ] Implement input validation
- [ ] Use environment variables for secrets
- [ ] Regular dependency updates

---

## 🤝 Contributing

### Development Workflow
1. Fork repository
2. Create branch: `git checkout -b feature/my-feature`
3. Make changes, add tests
4. Commit: `git commit -m "feat: Add feature"`
5. Push and open PR

### Code Style
- **Python**: PEP 8, use Black formatter
- **Go**: gofmt, meaningful names
- **JavaScript/TypeScript**: Prettier, ESLint

---

## 📚 Resources
- [Architecture](docs/architecture.md)
- [Research Background](docs/research_background.md)
- [FAQ](FAQ.md)
