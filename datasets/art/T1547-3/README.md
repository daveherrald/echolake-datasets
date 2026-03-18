# T1547-3: Boot or Logon Autostart Execution

**MITRE ATT&CK:** [T1547](https://attack.mitre.org/techniques/T1547)
**Technique:** Boot or Logon Autostart Execution
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547 -TestNumbers 3` — Leverage Virtual Channels to execute custom DLL during successful RDP session

## Telemetry (64 events)
- **Sysmon**: 17 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
