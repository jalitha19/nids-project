# Lightweight Network Intrusion Detection System (NIDS)

A Python-based NIDS that captures live network traffic and detects common attack patterns in real time. Alerts are displayed in the terminal with color-coded severity and logged in Suricata-style JSON format. A React dashboard provides a real-time visual feed.

Built as a blue team portfolio project demonstrating packet analysis, rule-based detection, structured logging, and SOC-style dashboarding.

---

## What it detects

| Attack type | Detection logic | Severity |
|---|---|---|
| Port scan | 15+ unique destination ports from one source in 10s | High |
| SYN flood | 100+ SYN-only packets from one source in 5s | Critical |
| ICMP ping sweep | 10+ ICMP packets from one source in 5s | Medium |
| SSH brute force | 5+ SYN attempts to port 22 from one source in 30s | High |

---

## Project structure

```
nids-project/
├── nids.py          # Entry point - wires sniffer to engine and output
├── sniffer.py       # Scapy packet capture and parsing (reference/standalone)
├── engine.py        # Rule-based detection engine with time-window tracking
├── output.py        # Color-coded CLI output and JSON alert logging
├── alerts.json      # Auto-created - one Suricata-style JSON alert per line
└── dashboard/
    ├── server/
    │   ├── index.js         # Express API that serves alerts.json
    │   └── package.json
    └── client/
        ├── src/
        │   ├── App.jsx      # Main React dashboard component
        │   ├── main.jsx     # React entry point
        │   └── index.css    # Tailwind directives + monospace font
        ├── index.html
        ├── vite.config.js
        ├── tailwind.config.js
        ├── postcss.config.js
        └── package.json
```

---

## How to run it locally

### Requirements

- Python 3.8+
- Node.js 18+
- A machine where you have root/admin access for raw packet capture

### 1. Install Python dependencies

```bash
pip install scapy colorama
```

### 2. Start the NIDS

```bash
sudo python3 nids.py
```

Optional flags:

```bash
sudo python3 nids.py -i eth0          # specify a network interface
sudo python3 nids.py -i eth0 -c 1000  # stop after 1000 packets
```

Alerts print to the terminal and append to `alerts.json` automatically.

### 3. Start the API server

```bash
cd dashboard/server
npm install
npm start
```

### 4. Start the React dashboard

```bash
cd dashboard/client
npm install
npm run dev
```

Visit `http://localhost:5173` in your browser. The dashboard polls for new alerts every 3 seconds.

---

## Example alert output (terminal)

```
2024-03-15 10:42:01  [ CRITICAL ]  192.168.1.105       SYN_FLOOD              143 SYN packets in 5s
2024-03-15 10:42:03  [   HIGH   ]  192.168.1.105       PORT_SCAN              22 unique ports in 10s
2024-03-15 10:42:07  [  MEDIUM  ]  10.0.0.20           ICMP_SWEEP             11 ICMP packets in 5s
```

## Example alert (alerts.json)

```json
{"timestamp": "2024-03-15T10:42:01.123456Z", "alert_type": "SYN_FLOOD", "src_ip": "192.168.1.105", "severity": "critical", "detail": "143 SYN packets in 5s"}
```

---

## Real-world tools that extend this project

| Tool | How it extends this project |
|---|---|
| **Snort** | Industry-standard NIDS. Compare your detection rules to Snort's rule syntax |
| **Suricata** | Modern multi-threaded IDS/IPS. Your `alerts.json` mimics its EVE JSON format exactly |
| **Wireshark** | GUI packet analyzer. Use it alongside this project to visually verify what you're capturing |
| **nmap** | Port scanner. Run `nmap -sS <target>` against a test VM to trigger your port scan and SYN flood rules |
| **Hydra** | SSH brute force tool. Use it in a lab environment to trigger your SSH brute force rule |
| **Elastic / Kibana** | Ship your `alerts.json` to an ELK stack and build dashboards identical to real SOC tooling |
| **SecLists** | Wordlists for password attacks (use in a lab only) |

---

## Disclaimer

This tool is for educational and authorized lab use only. Only run it on networks you own or have explicit permission to monitor. Do not use attack simulation tools (nmap, Hydra) against systems you do not own.
