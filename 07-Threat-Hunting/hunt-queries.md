# Threat Hunting Queries

## TH-001 — Attacker IP Discovery
**Goal:** Find all IPs attacking the environment
```spl
index=* sourcetype=wazuh
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| where isnotnull(src_ip)
| stats count as attacks,
  earliest(_time) as first_seen,
  latest(_time) as last_seen by src_ip
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M")
| sort -attacks
```
**Finding:** 10.128.124.9 made 1,391+ attempts

---

## TH-002 — Behavioral Baseline Deviation
**Goal:** Find abnormal activity spikes
```spl
index=* sourcetype=wazuh
| rex field=_raw "\"name\":\"(?P<agent>[^\"]+)\""
| bucket _time span=1h
| stats count by _time, agent
| eventstats avg(count) as avg stdev(count) as std by agent
| eval zscore=round((count-avg)/if(std=0,1,std),2)
| where zscore > 2
| table _time, agent, count, avg, zscore
```
**Finding:** 80x spike during Hydra attack

---

## TH-003 — Attack Timeline Reconstruction
**Goal:** Rebuild full kill chain step by step
```spl
index=* sourcetype=wazuh earliest=-7d
| rex field=_raw "\"description\":\"(?P<desc>[^\"]+)\""
| eval phase=case(
    match(desc,"scan"),"1-Recon",
    match(desc,"brute|auth fail"),"2-Credential Attack",
    match(desc,"session opened"),"3-Initial Access",
    match(desc,"sudo|ROOT"),"4-Privilege Escalation",
    1=1,"Other")
| where phase!="Other"
| table _time, phase, desc
| sort _time
```
**Finding:** Full T1046→T1110→T1078→T1548 chain

---

## TH-004 — IOC Correlation
**Goal:** Everything known bad IP did
```spl
index=* sourcetype=wazuh
| rex field=_raw "\"srcip\":\"(?P<src_ip>[^\"]+)\""
| where src_ip="10.128.124.9"
| rex field=_raw "\"description\":\"(?P<desc>[^\"]+)\""
| stats count by desc
| sort -count
| eval verdict="MALICIOUS - Known Attacker"
```
**Finding:** 1391 auth failures from Kali machine

---

## TH-005 — After Hours Login
**Goal:** Logins outside business hours
```spl
index=* sourcetype=wazuh "session opened"
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 7 OR hour > 21
| eval risk="After Hours - SUSPICIOUS"
| table _time, agent.name, hour, risk
```
**Finding:** Attack occurred at 19:00-21:00 IST
