# T1083-9: File and Directory Discovery

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083)
**Technique:** File and Directory Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1083 -TestNumbers 9` — Recursive Enumerate Files And Directories By Powershell

## Telemetry (823 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 776 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
