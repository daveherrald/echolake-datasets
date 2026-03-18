# T1546.010-1: AppInit DLLs

**MITRE ATT&CK:** [T1546.010](https://attack.mitre.org/techniques/T1546/010)
**Technique:** AppInit DLLs
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.010 -TestNumbers 1` — Install AppInit Shim

## Telemetry (75 events)
- **Sysmon**: 29 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
