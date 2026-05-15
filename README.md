# AI-Powered Network Intrusion Detection System (NIDS)

A real-time network packet analyzer built in C and Python, 
with AI-powered threat explanation via Claude API.

## Stack
- C + libpcap — raw packet capture
- Python — feature extraction and analysis
- ML — anomaly detection (coming Week 3)
- Claude API — threat explanation (coming Week 5)

## How to run

### Capture packets
```bash
sudo ./sniffer "tcp or udp" > packets.json
```

### Analyze
```bash
python3 reader.py
```

## Progress
- Week 1 ✅ — C sniffer, JSON output, Python analyzer
- Week 2 — Python bridge, flow aggregation, SQLite
- Week 3 — ML anomaly detection
- Week 4 — Claude API integration
- Week 5 — Live dashboard
