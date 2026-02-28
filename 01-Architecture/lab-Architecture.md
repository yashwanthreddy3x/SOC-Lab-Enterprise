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

## Tools & Versions
- Kali Linux — Hydra, nmap, wordlists
- Ubuntu 22.04 — Wazuh Agent v4.14
- Wazuh OVA v4.14 — Manager + Indexer + Dashboard
- Splunk Enterprise 10.0
- Shuffle SOAR — Cloud
- VirusTotal API v3
- Jira Service Management (Atlassian)
