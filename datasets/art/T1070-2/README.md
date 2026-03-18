# T1070-2: Indicator Removal

**MITRE ATT&CK:** [T1070](https://attack.mitre.org/techniques/T1070)
**Technique:** Indicator Removal
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070 -TestNumbers 2` — Indicator Manipulation using FSUtil

## Telemetry (77 events)
- **Sysmon**: 28 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
