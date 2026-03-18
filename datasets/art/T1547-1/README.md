# T1547-1: Boot or Logon Autostart Execution

**MITRE ATT&CK:** [T1547](https://attack.mitre.org/techniques/T1547)
**Technique:** Boot or Logon Autostart Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547 -TestNumbers 1` — Add a driver

## Telemetry (63 events)
- **Sysmon**: 18 events
- **Security**: 19 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
