# T1558.004-2: AS-REP Roasting

**MITRE ATT&CK:** [T1558.004](https://attack.mitre.org/techniques/T1558/004)
**Technique:** AS-REP Roasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.004 -TestNumbers 2` — Get-DomainUser with PowerView

## Telemetry (86 events)
- **Sysmon**: 35 events
- **Security**: 9 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
