# SPL Correlation Rules — SOC Lab
**Author:** Yashwanth Reddy Amireddy | **Lab:** Multi-Tier SOC Environment  
**Total Rules:** 15 | **Coverage:** T1110, T1548, T1078, T1021, T1046, T1059, T1053, T1098, T1136, T1003, T1027

---

## Rule SOC-001 — SSH Brute Force Detection (T1110)

**Purpose:** Detects SSH brute force attacks by identifying 5+ authentication failures in 2 minutes from same source IP.

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

**Why it works:** Buckets events into 2-minute windows, groups by source IP, triggers when threshold exceeded.

**False Positive Tuning:** Threshold raised from 3 to 5 to reduce noise from legitimate admin retries.

---

## Rule SOC-002 — Brute Force Single IP (T1110)

**Purpose:** Detects high-volume password attacks from a single IP address — classic automated brute force behavior.

**MITRE:** T1110.001 | TA0006 Credential Access

```spl
index=* sourcetype=wazuh
("authentication failed" OR "User login failed")
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| bucket _time span=5m
| stats count by _time, src_ip, agent_name
| where count >= 10
| eval severity="HIGH"
| eval mitre_technique="T1110.001"
| table _time, src_ip, agent_name, count, severity, mitre_technique
```

**Why it works:** Focuses on volume from single IP — distinguishes targeted brute force from distributed spray.

**False Positive Tuning:** Threshold at 10 per 5 min window — below this is normal admin retry behavior.

---

## Rule SOC-003 — Credential Stuffing Detection (T1110.004)

**Purpose:** Detects when attacker tries multiple different usernames from same IP — credential stuffing pattern.

**MITRE:** T1110.004 | TA0006 Credential Access

```spl
index=* sourcetype=wazuh
("authentication failed" OR "User login failed")
| rex field=_raw "\"dstuser\":\"(?P<username>[^\"]+)\""
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| bucket _time span=10m
| stats dc(username) as unique_users count by _time, src_ip, agent_name
| where unique_users >= 3
| eval severity="HIGH"
| eval mitre_technique="T1110.004"
| eval description="Credential Stuffing - Multiple usernames tried"
| table _time, src_ip, agent_name, unique_users, count, severity, mitre_technique
```

**Why it works:** `dc(username)` counts distinct usernames — 3+ unique users from same IP = stuffing pattern.

**False Positive Tuning:** Threshold of 3 distinct users — single user retries are excluded.

---

## Rule SOC-004 — Root Account Brute Force (T1110 CRITICAL)

**Purpose:** Detects targeted attacks against the root account — highest privilege target on Linux systems.

**MITRE:** T1110 | TA0006 Credential Access

```spl
index=* sourcetype=wazuh
("authentication failed" OR "User login failed")
| rex field=_raw "\"dstuser\":\"(?P<username>[^\"]+)\""
| where username="root"
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| stats count by src_ip, agent_name
| where count >= 3
| eval severity="CRITICAL"
| eval mitre_technique="T1110"
| eval description="Root account brute force attack"
| table src_ip, agent_name, count, severity, mitre_technique, description
```

**Why it works:** Filters specifically for root account targeting — any brute force against root is CRITICAL.

**False Positive Tuning:** Root login should never fail repeatedly in normal operations — low FP rate.

---

## Rule SOC-005 — Sudo Privilege Escalation (T1548.003)

**Purpose:** Detects successful and failed sudo escalation attempts — attacker gaining root from normal user.

**MITRE:** T1548.003 | TA0004 Privilege Escalation

```spl
index=* sourcetype=wazuh
("sudo" OR "sudo to ROOT")
| rex field=_raw "\"srcuser\":\"(?P<user>[^\"]+)\""
| rex field=_raw "\"description\":\"(?P<rule_desc>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| eval severity=if(like(rule_desc,"%ROOT%"),"CRITICAL","HIGH")
| eval mitre_technique="T1548.003"
| eval mitre_tactic="TA0004-Privilege Escalation"
| table _time, agent_name, user, rule_desc, severity, mitre_technique
| sort -severity
```

**Why it works:** Any sudo activity is flagged — CRITICAL if root session opened, HIGH for attempts.

**False Positive Tuning:** Excluded known maintenance window sudo activity from wazuh-server.

---

## Rule SOC-006 — Brute Force Succeeded (T1078 CRITICAL)

**Purpose:** Most critical rule — detects when brute force attack results in successful login. Indicates compromise.

**MITRE:** T1078 | TA0001 Initial Access

```spl
index=* sourcetype=wazuh
("authentication failed" OR "login failed" OR "session opened" OR "authentication success")
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| eval event_type=if(like(_raw,"%failed%"),"FAILURE","SUCCESS")
| bucket _time span=10m
| stats values(event_type) as events, count by _time, src_ip, agent_name
| where mvfind(events,"FAILURE")>=0 AND mvfind(events,"SUCCESS")>=0
| eval severity="CRITICAL"
| eval mitre_technique="T1078"
| eval description="Brute Force Succeeded - Valid Account Compromised"
| table _time, src_ip, agent_name, count, severity, description, mitre_technique
```

**Why it works:** Correlates FAILURE + SUCCESS from same IP in same window — brute force win pattern.

**False Positive Tuning:** Requires both failure AND success from same source IP — very low FP rate.

---

## Rule SOC-007 — PAM Login Failure Spike (T1110)

**Purpose:** Detects spikes in PAM authentication failures — Linux OS-level confirmation of brute force.

**MITRE:** T1110 | TA0006 Credential Access

```spl
index=* sourcetype=wazuh
"PAM: User login failed*"
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| bucket _time span=2m
| stats count by _time, agent_name
| where count >= 5
| eval severity="HIGH"
| eval mitre_technique="T1110"
| table _time, agent_name, count, severity, mitre_technique
```

**Why it works:** PAM failures confirm attacks at OS level — corroborates SSH-level brute force detections.

**False Positive Tuning:** Two independent log sources (SSH + PAM) confirming same attack = high confidence.

---

## Rule SOC-008 — High Severity Wazuh Alert Level 10+ 

**Purpose:** Catch-all for any Wazuh alert at level 10 or above — ensures no critical events are missed.

**MITRE:** Multiple | Various Tactics

```spl
index=* sourcetype=wazuh
| rex field=_raw "\"level\":(?P<rule_level>\d+)"
| rex field=_raw "\"description\":\"(?P<rule_desc>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| eval rule_level=tonumber(rule_level)
| where rule_level >= 10
| eval severity=case(rule_level>=13,"CRITICAL",rule_level>=10,"HIGH",1=1,"MEDIUM")
| table _time, agent_name, rule_level, rule_desc, severity, src_ip
| sort -rule_level
```

**Why it works:** Wazuh level 10+ indicates serious events — acts as safety net for any missed specific rules.

**False Positive Tuning:** Excluded wazuh-server's own admin sudo during maintenance windows.

---

## Rule SOC-009 — SSH Lateral Movement (T1021.004)

**Purpose:** Detects when same attacker IP targets multiple hosts — indicates lateral movement campaign.

**MITRE:** T1021.004 | TA0008 Lateral Movement

```spl
index=* sourcetype=wazuh
("authentication failed" OR "session opened")
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| bucket _time span=10m
| stats dc(agent_name) as targets, values(agent_name) as target_hosts, count by _time, src_ip
| where targets >= 2
| eval severity="HIGH"
| eval mitre_technique="T1021.004"
| eval mitre_tactic="TA0008-Lateral Movement"
| table _time, src_ip, targets, target_hosts, count, severity, mitre_technique
```

**Why it works:** Single IP hitting multiple agents = lateral movement. `dc()` counts distinct targets.

**False Positive Tuning:** Threshold of 2+ distinct hosts — single host retries are excluded.

---

## Rule SOC-010 — Attack Volume Anomaly

**Purpose:** Detects abnormal spikes in alert volume using statistical z-score — catches campaigns early.

**MITRE:** T1110 | TA0006 Credential Access

```spl
index=* sourcetype=wazuh
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| bucket _time span=5m
| stats count by _time, agent_name
| eventstats avg(count) as avg_count stdev(count) as std_count by agent_name
| eval zscore=round((count-avg_count)/if(std_count=0,1,std_count),2)
| where zscore > 3
| eval severity="HIGH"
| eval description="Abnormal alert volume - " + tostring(zscore) + "x above baseline"
| table _time, agent_name, count, avg_count, zscore, severity, description
```

**Why it works:** Z-score > 3 means 3 standard deviations above normal — statistically significant anomaly.

**False Positive Tuning:** Z-score threshold of 3 prevents normal fluctuations from triggering.

---

## Rule SOC-011 — New User Account Created (T1136)

**Purpose:** Detects creation of new local accounts — common persistence mechanism after initial access.

**MITRE:** T1136.001 | TA0003 Persistence

```spl
index=* sourcetype=wazuh
("new user" OR "useradd" OR "adduser")
| rex field=_raw "\"description\":\"(?P<rule_desc>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| eval severity="HIGH"
| eval mitre_technique="T1136.001"
| eval mitre_tactic="TA0003-Persistence"
| table _time, agent_name, rule_desc, severity, mitre_technique
```

**Why it works:** New account creation is rare in stable systems — any occurrence warrants investigation.

**False Positive Tuning:** Coordinate with sysadmins for planned account creations — whitelist known activity.

---

## Rule SOC-012 — Password Change Detected (T1098)

**Purpose:** Detects password changes that could indicate account takeover or credential manipulation.

**MITRE:** T1098 | TA0003 Persistence

```spl
index=* sourcetype=wazuh
("password changed" OR "passwd" OR "chpasswd")
| rex field=_raw "\"description\":\"(?P<rule_desc>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| eval severity="MEDIUM"
| eval mitre_technique="T1098"
| eval mitre_tactic="TA0003-Persistence"
| table _time, agent_name, rule_desc, severity, mitre_technique
```

**Why it works:** Password changes outside change management windows are suspicious persistence indicators.

**False Positive Tuning:** Correlate with change management tickets — exclude scheduled password rotations.

---

## Rule SOC-013 — After Hours Login (T1078)

**Purpose:** Detects successful logins outside business hours (before 7AM or after 9PM) — attacker behavior pattern.

**MITRE:** T1078 | TA0001 Initial Access

```spl
index=* sourcetype=wazuh
("session opened" OR "authentication success" OR "Accepted password")
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 7 OR hour > 21
| eval severity="MEDIUM"
| eval mitre_technique="T1078"
| eval description="Login outside business hours - Hour: " + tostring(hour)
| table _time, agent_name, src_ip, hour, severity, description, mitre_technique
```

**Why it works:** Legitimate users rarely log in at 3AM — after-hours activity is a strong IOC.

**False Positive Tuning:** Whitelist known on-call engineers and scheduled maintenance windows.

---

## Rule SOC-014 — Multiple Failed Sudo Attempts (T1548)

**Purpose:** Detects repeated sudo failures from same user — privilege escalation attempt pattern.

**MITRE:** T1548.003 | TA0004 Privilege Escalation

```spl
index=* sourcetype=wazuh
("sudo" AND ("incorrect password" OR "authentication failure" OR "NOT in sudoers"))
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| rex field=_raw "\"srcuser\":\"(?P<src_user>[^\"]+)\""
| bucket _time span=5m
| stats count by _time, agent_name, src_user
| where count >= 3
| eval severity="HIGH"
| eval mitre_technique="T1548.003"
| table _time, agent_name, src_user, count, severity, mitre_technique
```

**Why it works:** 3+ sudo failures in 5 minutes indicates a user trying to escalate without proper credentials.

**False Positive Tuning:** Threshold of 3 — single typo is normal, repeated failures are suspicious.

---

## Rule SOC-015 — SSH Key Modification (T1098.004)

**Purpose:** Detects modifications to SSH authorized_keys file — attacker adding persistent backdoor access.

**MITRE:** T1098.004 | TA0003 Persistence

```spl
index=* sourcetype=wazuh
("authorized_keys" OR ".ssh" OR "ssh_host")
| rex field=_raw "\"description\":\"(?P<rule_desc>[^\"]+)\""
| rex field=_raw "\"name\":\"(?P<agent_name>[^\"]+)\""
| eval severity="HIGH"
| eval mitre_technique="T1098.004"
| eval mitre_tactic="TA0003-Persistence"
| table _time, agent_name, rule_desc, severity, mitre_technique
```

**Why it works:** SSH key additions give permanent backdoor access — should never happen without change ticket.

**False Positive Tuning:** Any authorized_keys change is HIGH severity — verify with user immediately.

---

## Summary Table

| Rule ID | Detection | MITRE Technique | Tactic | Severity |
|---------|-----------|-----------------|--------|----------|
| SOC-001 | SSH Brute Force | T1110.001 | TA0006 | HIGH |
| SOC-002 | Brute Force Single IP | T1110.001 | TA0006 | HIGH |
| SOC-003 | Credential Stuffing | T1110.004 | TA0006 | HIGH |
| SOC-004 | Root Account Attack | T1110 | TA0006 | CRITICAL |
| SOC-005 | Sudo Escalation | T1548.003 | TA0004 | CRITICAL |
| SOC-006 | Brute Force Succeeded | T1078 | TA0001 | CRITICAL |
| SOC-007 | PAM Login Failure | T1110 | TA0006 | HIGH |
| SOC-008 | High Severity Alert | Multiple | Various | HIGH |
| SOC-009 | SSH Lateral Movement | T1021.004 | TA0008 | HIGH |
| SOC-010 | Volume Anomaly | T1110 | TA0006 | HIGH |
| SOC-011 | New User Created | T1136.001 | TA0003 | HIGH |
| SOC-012 | Password Changed | T1098 | TA0003 | MEDIUM |
| SOC-013 | After Hours Login | T1078 | TA0001 | MEDIUM |
| SOC-014 | Failed Sudo Attempts | T1548.003 | TA0004 | HIGH |
| SOC-015 | SSH Key Modified | T1098.004 | TA0003 | HIGH |
