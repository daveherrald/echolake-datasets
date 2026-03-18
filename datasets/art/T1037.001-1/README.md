# T1037.001-1: Logon Script (Windows)

**MITRE ATT&CK:** [T1037.001](https://attack.mitre.org/techniques/T1037/001)
**Technique:** Logon Script (Windows)
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1037.001 -TestNumbers 1` — Logon Scripts

## Telemetry (65 events)
- **Sysmon**: 19 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
