# T1496-2: Resource Hijacking

**MITRE ATT&CK:** [T1496](https://attack.mitre.org/techniques/T1496)
**Technique:** Resource Hijacking
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1496 -TestNumbers 2` — Windows - Simulate CPU Load with PowerShell

## Telemetry (1211 events)
- **Sysmon**: 77 events
- **Security**: 22 events
- **Powershell**: 1112 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
