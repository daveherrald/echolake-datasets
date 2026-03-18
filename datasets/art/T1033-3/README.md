# T1033-3: System Owner/User Discovery

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033)
**Technique:** System Owner/User Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1033 -TestNumbers 3` — Find computers where user has session - Stealth mode (PowerView)

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
