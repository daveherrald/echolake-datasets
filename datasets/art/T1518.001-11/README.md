# T1518.001-11: Security Software Discovery

**MITRE ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001)
**Technique:** Security Software Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1518.001 -TestNumbers 11` — Get Windows Defender exclusion settings using WMIC

## Telemetry (83 events)
- **Sysmon**: 33 events
- **Security**: 16 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
