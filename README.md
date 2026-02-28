# SOC-Lab-Enterprise
## Overview
A production-grade Security Operations Center lab 
environment built to simulate real-world threat 
detection, investigation, and automated response.

## Architecture
```
Kali (Attacker) → Ubuntu (Endpoint+Wazuh Agent) 
→ Wazuh OVA (Manager+Forwarder) → Splunk SIEM 
→ Shuffle SOAR → VirusTotal + Jira
```

## What I Built & Demonstrated

| Phase | What I Did | Proof |
|-------|-----------|-------|
| Attack Simulation | SSH brute force, nmap, privilege escalation | Screenshots |
| Log Ingestion | Linux auth, syslog → Wazuh → Splunk | 14,186 events |
| SPL Rules | 15 correlation rules | Splunk Alerts page |
| Alert Triage | 50+ alerts documented | CSV file |
| MITRE Mapping | 9 tactics, 12 techniques | Excel + Wazuh dashboard |
| SOAR Automation | Webhook→VT→Jira in 45 sec | Jira tickets SOC-1,2 |
| Threat Hunting | 5 proactive hunt queries | Splunk Reports |
| IR Report | Full NIST 800-61 cycle | INC-2026-001 |

## Key Metrics
- **MTTD** (Mean Time to Detect): 2 minutes
- **MTTR** (Mean Time to Respond): 5 minutes  
- **SOAR Response Time**: 45 seconds
- **Alerts Triaged**: 50+
- **False Positive Rate**: < 20%

## MITRE ATT&CK Coverage
| Technique | ID | Tactic |
|-----------|-----|--------|
| Password Guessing | T1110.001 | Credential Access |
| Valid Accounts | T1078 | Initial Access |
| Sudo Escalation | T1548.003 | Privilege Escalation |
| SSH Services | T1021.004 | Lateral Movement |
| Unix Shell | T1059.004 | Execution |
| Cron Job | T1053.003 | Persistence |

## Tools Used
- Kali Linux, Hydra, nmap
- Ubuntu 22.04, Wazuh v4.14
- Splunk Enterprise 10.0
- Shuffle SOAR (shuffler.io)
- VirusTotal API v3
- Jira Service Management

## Lab Files
- 📊 [50+ Alert Documentation](04-Alert-Documentation/)
- 📋 [SPL Correlation Rules](03-SPL-Correlation-Rules/)
- 🎯 [MITRE ATT&CK Coverage](05-MITRE-ATT&CK/)
- 🤖 [SOAR Playbook](06-SOAR-Playbook/)
- 🔍 [Threat Hunt Queries](07-Threat-Hunting/)
- 📝 [IR Post-Incident Report](08-IR-Report/)

## Author
**Yashwanth Reddy Amireddy**  
L1 SOC Analyst | Security Operations  
Feb 2026
