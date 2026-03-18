# T1546.012-3: Image File Execution Options Injection

**MITRE ATT&CK:** [T1546.012](https://attack.mitre.org/techniques/T1546/012)
**Technique:** Image File Execution Options Injection
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.012 -TestNumbers 3` — GlobalFlags in Image File Execution Options

## Telemetry (124 events)
- **Sysmon**: 55 events
- **Security**: 25 events
- **Powershell**: 43 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
