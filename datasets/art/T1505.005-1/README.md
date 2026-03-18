# T1505.005-1: Terminal Services DLL

**MITRE ATT&CK:** [T1505.005](https://attack.mitre.org/techniques/T1505/005)
**Technique:** Terminal Services DLL
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1505.005 -TestNumbers 1` — Simulate Patching termsrv.dll

## Telemetry (128 events)
- **Sysmon**: 58 events
- **Security**: 25 events
- **Powershell**: 43 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
