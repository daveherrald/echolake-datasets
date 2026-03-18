# T1562.001-21: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 21` — Stop and Remove Arbitrary Security Windows Service

## Telemetry (93 events)
- **Sysmon**: 35 events
- **Security**: 8 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
