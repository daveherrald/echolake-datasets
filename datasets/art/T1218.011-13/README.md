# T1218.011-13: Rundll32

**MITRE ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011)
**Technique:** Rundll32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.011 -TestNumbers 13` — Rundll32 with desk.cpl

## Telemetry (93 events)
- **Sysmon**: 37 events
- **Security**: 23 events
- **Powershell**: 30 events
- **Application**: 2 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
