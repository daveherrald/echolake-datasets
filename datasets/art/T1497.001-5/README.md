# T1497.001-5: System Checks

**MITRE ATT&CK:** [T1497.001](https://attack.mitre.org/techniques/T1497/001)
**Technique:** System Checks
**Tactic(s):** defense-evasion, discovery
**ART Test:** `Invoke-AtomicTest T1497.001 -TestNumbers 5` — Detect Virtualization Environment via WMI Manufacturer/Model Listing (Windows)

## Telemetry (67 events)
- **Sysmon**: 28 events
- **Security**: 10 events
- **Powershell**: 29 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
