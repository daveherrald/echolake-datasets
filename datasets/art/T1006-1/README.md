# T1006-1: Direct Volume Access

**MITRE ATT&CK:** [T1006](https://attack.mitre.org/techniques/T1006)
**Technique:** Direct Volume Access
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1006 -TestNumbers 1` — Read volume boot sector via DOS device path (PowerShell)

## Telemetry (80 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
