# SPL Correlation Rules

## Rule SOC-001 — SSH Brute Force Detection (T1110)

**Purpose:** Detects SSH brute force attacks by 
identifying 5+ authentication failures in 2 minutes 
from same source IP.

**MITRE:** T1110.001 | TA0006 Credential Access
```spl
index=* sourcetype=wazuh
("authentication failed" OR "User login failed")
| bucket _time span=2m
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| stats count by _time, agent_name, src_ip
| where count >= 5
| eval severity="HIGH"
| eval mitre_technique="T1110.001"
| table _time, agent_name, src_ip, count, severity, mitre_technique
```

**Why it works:** Buckets events into 2-minute windows,
groups by source IP, triggers when threshold exceeded.

**False Positive Tuning:** Threshold raised from 3 to 5
to reduce noise from legitimate admin retries.

---
