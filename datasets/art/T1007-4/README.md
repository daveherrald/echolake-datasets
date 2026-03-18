# T1007-4: System Service Discovery

**MITRE ATT&CK:** [T1007](https://attack.mitre.org/techniques/T1007)
**Technique:** System Service Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1007 -TestNumbers 4` — Get-Service Execution

## Telemetry (80 events)
- **Sysmon**: 31 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
