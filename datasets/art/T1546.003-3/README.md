# T1546.003-3: Windows Management Instrumentation Event Subscription

**MITRE ATT&CK:** [T1546.003](https://attack.mitre.org/techniques/T1546/003)
**Technique:** Windows Management Instrumentation Event Subscription
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.003 -TestNumbers 3` — Windows MOFComp.exe Load MOF File

## Telemetry (99 events)
- **Sysmon**: 47 events
- **Security**: 13 events
- **Powershell**: 37 events
- **Application**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
