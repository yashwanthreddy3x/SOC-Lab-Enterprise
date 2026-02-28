# Shuffle SOAR Playbook

## Workflow: SOC Automation

### Pipeline
```
Splunk Alert Fires
      ↓
Shuffle Webhook Receives
      ↓
Shuffle Tools Extracts IP
      ↓
VirusTotal API Checks IP
      ↓
Jira Ticket Auto-Created
```

### Steps Configured
1. **Webhook** — Receives Splunk alert payload
2. **Shuffle Tools** — Regex extracts source IP
3. **VirusTotal v3** — get_an_ip_address_report
4. **Jira** — post_create_issue → Project SOC

### Results
- Jira ticket SOC-1 created ✅
- Jira ticket SOC-2 created ✅
- Response time: 45 seconds
- Zero manual intervention required

### Jira Ticket Content
- Source IP from alert
- Agent name
- Rule description
- MITRE technique
- Severity level
- Action required
