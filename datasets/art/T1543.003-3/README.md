# T1543.003-3: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 3` — Service Installation PowerShell

## Telemetry (106 events)
- **Sysmon**: 49 events
- **Security**: 18 events
- **Powershell**: 37 events
- **System**: 1 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
