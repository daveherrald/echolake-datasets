# T1007-6: System Service Discovery

**MITRE ATT&CK:** [T1007](https://attack.mitre.org/techniques/T1007)
**Technique:** System Service Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1007 -TestNumbers 6` — System Service Discovery - Windows Scheduled Tasks (schtasks)

## Telemetry (66 events)
- **Sysmon**: 20 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
