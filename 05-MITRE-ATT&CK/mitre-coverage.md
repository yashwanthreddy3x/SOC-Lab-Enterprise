# MITRE ATT&CK Coverage

## Coverage Summary
- **Tactics Covered:** 8
- **Techniques Mapped:** 12
- **Lab Period:** Feb 26-27, 2026

## Full Mapping Table

| # | ID | Technique | Tactic | Detected | SPL Rule |
|---|-----|-----------|--------|----------|----------|
| 1 | T1110.001 | Password Guessing | TA0006 Credential Access | YES | SOC-001 |
| 2 | T1110.004 | Credential Stuffing | TA0006 Credential Access | YES | SOC-003 |
| 3 | T1078 | Valid Accounts | TA0001 Initial Access | YES | SOC-006 |
| 4 | T1548.003 | Sudo Caching | TA0004 Privilege Escalation | YES | SOC-005 |
| 5 | T1021.004 | SSH Remote Services | TA0008 Lateral Movement | YES | SOC-009 |
| 6 | T1046 | Network Service Discovery | TA0043 Reconnaissance | YES | SOC-016 |
| 7 | T1059.004 | Unix Shell | TA0002 Execution | YES | SOC-020 |
| 8 | T1053.003 | Cron Job | TA0003 Persistence | YES | SOC-018 |
| 9 | T1098.004 | SSH Authorized Keys | TA0003 Persistence | YES | SOC-015 |
| 10 | T1003.008 | /etc/passwd /etc/shadow | TA0006 Credential Access | YES | SOC-017 |
| 11 | T1136.001 | Create Local Account | TA0003 Persistence | YES | SOC-011 |
| 12 | T1027 | Obfuscated Files | TA0005 Defense Evasion | YES | SOC-019 |

## Tactics Covered
- TA0001 Initial Access
- TA0002 Execution
- TA0003 Persistence
- TA0004 Privilege Escalation
- TA0005 Defense Evasion
- TA0006 Credential Access
- TA0008 Lateral Movement
- TA0043 Reconnaissance
```
