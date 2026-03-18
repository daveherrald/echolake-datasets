# T1204.002-13: Malicious File

**MITRE ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002)
**Technique:** Malicious File
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1204.002 -TestNumbers 13` — Simulate Click-Fix via Downloaded BAT File

## Telemetry (100 events)
- **Sysmon**: 44 events
- **Security**: 16 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
