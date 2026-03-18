# T1012-5: Query Registry

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012)
**Technique:** Query Registry
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1012 -TestNumbers 5` — Check Software Inventory Logging (SIL) status via Registry

## Telemetry (59 events)
- **Sysmon**: 21 events
- **Security**: 12 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
