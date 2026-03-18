# T1204.002-12: Malicious File

**MITRE ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002)
**Technique:** Malicious File
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1204.002 -TestNumbers 12` — ClickFix Campaign - Abuse RunMRU to Launch mshta via PowerShell

## Telemetry (92 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
