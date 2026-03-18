# T1025-1: Data from Removable Media

**MITRE ATT&CK:** [T1025](https://attack.mitre.org/techniques/T1025)
**Technique:** Data from Removable Media
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1025 -TestNumbers 1` — Identify Documents on USB and Removable Media via PowerShell

## Telemetry (106 events)
- **Sysmon**: 41 events
- **Security**: 22 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
