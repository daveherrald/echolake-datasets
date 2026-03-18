# T1083-5: File and Directory Discovery

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083)
**Technique:** File and Directory Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1083 -TestNumbers 5` — Simulating MAZE Directory Enumeration

## Telemetry (102 events)
- **Sysmon**: 29 events
- **Security**: 17 events
- **Powershell**: 56 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
