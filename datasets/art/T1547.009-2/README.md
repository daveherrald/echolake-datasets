# T1547.009-2: Shortcut Modification

**MITRE ATT&CK:** [T1547.009](https://attack.mitre.org/techniques/T1547/009)
**Technique:** Shortcut Modification
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.009 -TestNumbers 2` — Create shortcut to cmd in startup folders

## Telemetry (79 events)
- **Sysmon**: 30 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
