# T1547.004-3: Winlogon Helper DLL

**MITRE ATT&CK:** [T1547.004](https://attack.mitre.org/techniques/T1547/004)
**Technique:** Winlogon Helper DLL
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.004 -TestNumbers 3` — Winlogon Notify Key Logon Persistence - PowerShell

## Telemetry (83 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
