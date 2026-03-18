# T1207-1: Rogue Domain Controller

**MITRE ATT&CK:** [T1207](https://attack.mitre.org/techniques/T1207)
**Technique:** Rogue Domain Controller
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1207 -TestNumbers 1` — DCShadow (Active Directory)

## Telemetry (105 events)
- **Sysmon**: 38 events
- **Security**: 13 events
- **Powershell**: 54 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
