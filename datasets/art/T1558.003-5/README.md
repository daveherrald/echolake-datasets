# T1558.003-5: Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
**Technique:** Kerberoasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.003 -TestNumbers 5` — Request All Tickets via PowerShell

## Telemetry (110 events)
- **Sysmon**: 39 events
- **Security**: 16 events
- **Powershell**: 47 events
- **Application**: 1 events
- **Taskscheduler**: 7 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
