# T1547.004-4: Winlogon Helper DLL

**MITRE ATT&CK:** [T1547.004](https://attack.mitre.org/techniques/T1547/004)
**Technique:** Winlogon Helper DLL
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.004 -TestNumbers 4` — Winlogon HKLM Shell Key Persistence - PowerShell

## Telemetry (90 events)
- **Sysmon**: 39 events
- **Security**: 11 events
- **Powershell**: 38 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
