# T1036.004-1: Masquerade Task or Service

**MITRE ATT&CK:** [T1036.004](https://attack.mitre.org/techniques/T1036/004)
**Technique:** Masquerade Task or Service
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.004 -TestNumbers 1` — Creating W32Time similar named service using schtasks

## Telemetry (107 events)
- **Sysmon**: 46 events
- **Security**: 22 events
- **Powershell**: 35 events
- **System**: 1 events
- **Wmi**: 1 events
- **Taskscheduler**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
