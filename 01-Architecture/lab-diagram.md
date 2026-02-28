# Lab Architecture

## Network Diagram
```
Kali Linux (10.128.124.9)  ← Attacker
        ↓ SSH Brute Force
Ubuntu12 (10.128.124.88)   ← Victim Endpoint
        ↓ Wazuh Agent
Wazuh OVA (10.128.124.80)  ← XDR Manager + Splunk Forwarder
        ↓ Port 9997
Splunk SIEM (10.128.124.166) ← Detection + Correlation
        ↓ Webhook
Shuffle SOAR (shuffler.io)   ← Automation
        ↓                ↓
  VirusTotal API      Jira Tickets
  (IOC Enrichment)   (Auto-created)
```

## Components
- **Kali Linux** — Adversary simulation (Hydra, nmap)
- **Ubuntu 22.04** — Endpoint with Wazuh agent
- **Wazuh v4.14** — XDR detection and log forwarding
- **Splunk Enterprise** — SIEM correlation and alerting
- **Shuffle SOAR** — Automated incident response
