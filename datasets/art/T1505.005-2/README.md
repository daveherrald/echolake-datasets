# T1505.005-2: Terminal Services DLL

**MITRE ATT&CK:** [T1505.005](https://attack.mitre.org/techniques/T1505/005)
**Technique:** Terminal Services DLL
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1505.005 -TestNumbers 2` — Modify Terminal Services DLL Path

## Telemetry (119 events)
- **Sysmon**: 49 events
- **Security**: 17 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
