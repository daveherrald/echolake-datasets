# T1220-2: XSL Script Processing

**MITRE ATT&CK:** [T1220](https://attack.mitre.org/techniques/T1220)
**Technique:** XSL Script Processing
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1220 -TestNumbers 2` — MSXSL Bypass using remote files

## Telemetry (82 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
