# T1547-2: Boot or Logon Autostart Execution

**MITRE ATT&CK:** [T1547](https://attack.mitre.org/techniques/T1547)
**Technique:** Boot or Logon Autostart Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547 -TestNumbers 2` — Driver Installation Using pnputil.exe

## Telemetry (86 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
