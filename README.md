# Lightweight Network Intrusion Detection System (NIDS)

A Python-based network intrusion detection system that captures live network traffic and detects common attack patterns in real time.

## What this project does

- Captures live TCP, UDP, and ICMP packets using Scapy
- Detects port scans, SYN flood attempts, ICMP ping sweeps, and SSH brute force patterns
- Outputs color-coded alerts to the terminal with timestamp, source IP, attack type, and severity
- Logs alerts in Suricata-style JSON format to `alerts.json`
- Displays a real-time alert dashboard built with React, Vite, and Tailwind CSS

## Status

Under active development. Built as a portfolio project for blue team / defensive security internship applications.

## Tech stack

- Python 3, Scapy, colorama
- React, Vite, Tailwind CSS
- Node.js / Express (dashboard API)