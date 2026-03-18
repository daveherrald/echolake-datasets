# T1020-2: Automated Exfiltration

**MITRE ATT&CK:** [T1020](https://attack.mitre.org/techniques/T1020)
**Technique:** Automated Exfiltration
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1020 -TestNumbers 2` — Exfiltration via Encrypted FTP

## Telemetry (103 events)
- **Sysmon**: 41 events
- **Security**: 22 events
- **Powershell**: 34 events
- **Taskscheduler**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
