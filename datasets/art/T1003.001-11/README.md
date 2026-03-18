# T1003.001-11: LSASS Memory

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
**Technique:** LSASS Memory
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.001 -TestNumbers 11` — Dump LSASS with createdump.exe from .Net v5

## Telemetry (115 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 59 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
