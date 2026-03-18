# T1083-7: File and Directory Discovery

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083)
**Technique:** File and Directory Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1083 -TestNumbers 7` — ESXi - Enumerate VMDKs available on an ESXi Host

## Telemetry (75 events)
- **Sysmon**: 27 events
- **Security**: 13 events
- **Powershell**: 34 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
