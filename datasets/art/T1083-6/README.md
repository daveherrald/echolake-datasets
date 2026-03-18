# T1083-6: File and Directory Discovery

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083)
**Technique:** File and Directory Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1083 -TestNumbers 6` — Launch DirLister Executable

## Telemetry (93 events)
- **Sysmon**: 36 events
- **Security**: 9 events
- **Powershell**: 46 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
