# T1547.004-5: Winlogon Helper DLL

**MITRE ATT&CK:** [T1547.004](https://attack.mitre.org/techniques/T1547/004)
**Technique:** Winlogon Helper DLL
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.004 -TestNumbers 5` — Winlogon HKLM Userinit Key Persistence - PowerShell

## Telemetry (76 events)
- **Sysmon**: 27 events
- **Security**: 11 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
