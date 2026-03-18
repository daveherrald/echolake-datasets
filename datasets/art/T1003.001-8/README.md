# T1003.001-8: LSASS Memory

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
**Technique:** LSASS Memory
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.001 -TestNumbers 8` — Dump LSASS.exe Memory using Out-Minidump.ps1

## Telemetry (95 events)
- **Sysmon**: 36 events
- **Security**: 17 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
