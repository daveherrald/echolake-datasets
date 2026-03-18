# T1003.001-3: LSASS Memory

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
**Technique:** LSASS Memory
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.001 -TestNumbers 3` — Dump LSASS.exe Memory using direct system calls and API unhooking

## Telemetry (62 events)
- **Sysmon**: 16 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
