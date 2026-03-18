# PAWS Operation Yarn Ball

Full multi-stage attack simulation on a Windows Active Directory environment (pawsitivevibes.local) with 7 VMs. Combines AI-driven persona simulation with a realistic Sliver C2 attack chain.

## Overview

- **~820K events** across 12 data sources
- **7 hosts**: 1 domain controller (Server 2022), 1 executive workstation, 1 IT admin workstation, 4 employee workstations (Windows 11)
- **Background activity**: 6 employee personas generating realistic daily work patterns (browsing, email, file access) via LLM-driven planning
- **Attack**: 10-stage Sliver C2 operation from initial access through ransomware deployment and log clearing

## Attack Stages

1. Reconnaissance — system, network, user, and group enumeration
2. Beacon deployment — Sliver implant via scheduled task and registry persistence
3. Credential harvesting — LSASS access, unsecured credential discovery
4. Lateral movement — WinRM to IT admin workstation, PsExec to domain controller
5. Data exfiltration — sensitive files exfiltrated over C2 channel
6. Ransomware — file encryption across multiple hosts
7. Log clearing — Windows event log destruction

## Data Sources

| File | Events | Description |
|------|--------|-------------|
| sysmon.jsonl.gz | 566,793 | Sysmon operational events (all 7 hosts) |
| zeek_conn.jsonl.gz | 129,341 | Zeek connection logs |
| zeek_http.jsonl.gz | 39,399 | Zeek HTTP logs (includes C2 beacon traffic) |
| security.jsonl.gz | 32,414 | Windows Security events (logon, process creation) |
| wmi.jsonl.gz | 20,421 | WMI activity events |
| proxylog.jsonl.gz | 17,848 | Squid proxy access logs (includes C2 traffic) |
| taskscheduler.jsonl.gz | 4,872 | Task Scheduler events |
| powershell.jsonl.gz | 2,582 | PowerShell script block and module logging |
| system.jsonl.gz | 2,224 | Windows System event log |
| application.jsonl.gz | 2,162 | Windows Application event log |
| zeek_dns.jsonl.gz | 1,845 | Zeek DNS logs (includes C2 domain lookups) |
| wineventlog_other.jsonl.gz | 7 | Directory Service, DNS Server Audit |

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Discovery | T1082, T1016, T1033, T1069, T1018 |
| Command and Control | T1071, T1071.004 |
| Defense Evasion | T1218, T1070.001 |
| Execution | T1053, T1569.002 |
| Persistence | T1053, T1547.001 |
| Privilege Escalation | T1053, T1547.001 |
| Credential Access | T1552 |
| Lateral Movement | T1021.006, T1021.002 |
| Exfiltration | T1041 |
| Impact | T1486 |

## Environment

- **Domain**: pawsitivevibes.local
- **Hosts**: PAWS-DC01, PAWS-EXEC01, PAWS-IT01, PAWS-WS01–WS04
- **Instrumentation**: Sysmon v15.15 (sysmon-modular config), Windows audit policy with command-line logging, PowerShell script block and module logging
- **Network monitoring**: Zeek (conn, dns, http) on VLAN span port, Squid proxy on DC01
- **Collection**: Cribl Edge

## License

CC0 1.0 Universal (Public Domain Dedication). See [LICENSE](../../LICENSE).
