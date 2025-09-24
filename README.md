![Python](https://img.shields.io/badge/python-v3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Security](https://img.shields.io/badge/security-threat--detection-red.svg)
# Threat Detection Platform

A real-time security monitoring system that ingests multi-format data sources, performs threat analysis using MITRE ATT&CK framework integration, and provides automated response capabilities.

# Live Demo & Full Version Screenshots

Experience the full Security Detection Dashboard in action:  
[Open Live Demo](https://6zaaisxqmaeazazthcbosn.streamlit.app)

## 💻 Full Version (Real Data)

The dashboard includes real-time threat feed, analytics, and geographic threat mapping:

![Dashboard Overview](pic6.png)  


![Geographic Threat Distribution](pic5.png)  


![Analytics & MITRE Tab](pic4.png)  


![Detailed Threat View](pic3.png)  


![Advanced Analytics](pic2.png)  


![MITRE Insights](pic.png)  


## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │───▶│  Detection Engine │───▶│  Response & UI  │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • JSON/JSONL    │    │ • Pattern Match  │    │ • Auto IP Block │
│ • PCAP Files    │    │ • MITRE Mapping  │    │ • Email Alerts  │
│ • System Logs   │    │ • Geo Analysis   │    │ • Live Dashboard│
│ • Network Data  │    │ • ML Scoring     │    │ • Threat Maps   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                       ┌──────▼──────┐
                       │ PostgreSQL  │
                       │ Threat Intel│
                       └─────────────┘
```

## Key Features

**Multi-Source Data Ingestion**
- JSON/JSONL log processing with async streaming
- PCAP network traffic analysis using Scapy
- Real-time log file monitoring and parsing
- Configurable batch processing with queue management

**Advanced Threat Detection**
- MITRE ATT&CK technique classification and scoring  
- Geographic IP reputation analysis with threat mapping
- Pattern-based detection using regex and custom rules
- Behavioral analysis for repeat offender identification

**Automated Response System**
- Real-time IP blocking via iptables integration
- Email alerting for critical and high-severity threats
- Interactive threat maps with geographic visualization
- Persistent threat intelligence storage in PostgreSQL

**Monitoring Dashboard**
- Real-time threat feed with severity classification
- Geographic threat distribution analysis  
- MITRE technique trending and statistics
- Executive-level reporting and metrics

## Technical Stack

- **Backend**: Python (asyncio, asyncpg, aiohttp)
- **Database**: PostgreSQL with JSONB indexing
- **Network Analysis**: Scapy for packet processing
- **Visualization**: Streamlit dashboard, Folium maps
- **Containerization**: Docker with multi-stage builds
- **Security Integration**: MITRE ATT&CK framework

## Quick Start

### Prerequisites

```bash
# Required dependencies
Python 3.11+
PostgreSQL 13+
Docker (optional)
```

### Installation

1. **Clone and Setup Environment**
```bash
git clone https://github.com/yourusername/threat-detection-platform.git
cd threat-detection-platform
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Database Setup**
```bash
# Using Docker (recommended)
docker run --name security-db -e POSTGRES_PASSWORD=your_password -p 5432:5432 -d postgres

# Create database and tables
python -c "
import asyncio
from src.db import threat_db
asyncio.run(threat_db.init_pool())
"
```

3. **Configuration**
```bash
# Copy environment template
cp .env.example .env
# Edit .env with your database credentials and email settings
```

4. **Run Detection Engine**
```bash
# Process sample data
python -m src.ingestion.consumer

# Launch dashboard
streamlit run src/dashboard/streamlit_app.py
```

## Usage Examples

### Processing Network Traffic

```python
from src.ingestion.base_ingestor import BaseIngestor
import asyncio

async def analyze_pcap():
    ingestor = BaseIngestor("network_analyzer")
    await ingestor.start()
    
    async for event in ingestor.ingest_file("capture.pcap"):
        print(f"Threat detected: {event.ip} - {event.severity}")
        print(f"MITRE techniques: {event.mitre}")
```

### Custom Threat Rules

```python
# Add custom detection patterns
custom_patterns = {
    "cryptocurrency_mining": r"(xmrig|minergate|coinhive)",
    "reverse_shell": r"bash\s+-i|nc\s+-e",
    "data_exfiltration": r"curl.*-F|scp.*-r"
}
```

### Dashboard Access

Navigate to `http://localhost:8501` after launching the Streamlit dashboard to view:
- Live threat monitoring feed
- Geographic attack distribution maps  
- MITRE ATT&CK technique analysis
- Threat statistics and trending

## Configuration

### Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/security_db
REDIS_URL=redis://localhost:6379/0

# Email Alerting
SEND_EMAIL=your-email@domain.com
EMAIL_PASS=your-app-password
ALERT_EMAIL=security-team@company.com

# Processing Settings
BATCH_SIZE=50
QUEUE_SIZE=1000
MAX_WORKERS=4
```

### Detection Tuning

Modify threat scoring thresholds in `src/ingestion/base_ingestor.py`:

```python
# Severity scoring thresholds
if score >= 15:
    severity = "critical"    # Auto-ban + email + map
elif score >= 10:
    severity = "high"        # Email alert
elif score >= 5:
    severity = "medium"      # Log and monitor
```

## Development

### Running Tests

```bash
# Unit tests
python -m pytest tests/unit/

# Integration tests with live database
python -m pytest tests/integration/

# Generate test data
python tests/generate_test_threats.py
```

### Adding New Data Sources

Extend the `BaseIngestor` class for new input formats:

```python
class CustomLogIngestor(BaseIngestor):
    async def parse_data(self, data: bytes) -> List[Event]:
        # Implement custom parsing logic
        pass
```

### Code Style

```bash
# Format code
black src/ tests/
pylint src/
```

## Performance

**Tested Throughput:**
- 10,000+ events per minute processing
- Sub-2 second alert generation for critical threats
- Geographic lookups cached for performance
- Batch database operations for efficiency

**Resource Requirements:**
- Memory: 512MB minimum, 2GB recommended
- CPU: 2 cores minimum for concurrent processing
- Storage: PostgreSQL requires ~100MB per 10k events

## Security Considerations

**Network Security:**
- Dashboard runs on localhost by default
- Database connections use SSL in production
- IP blocking requires root privileges for iptables

**Data Privacy:**
- Raw packet data truncated to prevent sensitive data storage
- Geographic data cached but IP addresses not permanently logged
- Email alerts contain summarized threat information only

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Add tests for new functionality
4. Ensure all tests pass: `python -m pytest`
5. Submit a pull request with clear description

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Kubernetes deployment manifests
- [ ] REST API for external integrations  
- [ ] Machine learning model training pipeline
- [ ] Integration with popular SIEM platforms
- [ ] Advanced behavioral analysis algorithms
- [ ] Zero-trust policy engine integration

---

**Built for security professionals who need real-time threat visibility and automated response capabilities.**
