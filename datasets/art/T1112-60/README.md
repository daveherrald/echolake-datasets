# T1112-60: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 60` — Modify Internet Zone Protocol Defaults in Current User Registry - PowerShell

## Telemetry (67 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 31 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
