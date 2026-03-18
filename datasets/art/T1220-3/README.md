# T1220-3: XSL Script Processing

**MITRE ATT&CK:** [T1220](https://attack.mitre.org/techniques/T1220)
**Technique:** XSL Script Processing
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1220 -TestNumbers 3` — WMIC bypass using local XSL file

## Telemetry (88 events)
- **Sysmon**: 39 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
