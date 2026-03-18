# T1003.001-2: LSASS Memory

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
**Technique:** LSASS Memory
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.001 -TestNumbers 2` — Dump LSASS.exe Memory using comsvcs.dll

## Telemetry (65 events)
- **Sysmon**: 15 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
