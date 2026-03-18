# T1562.001-14: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 14` — AMSI Bypass - Remove AMSI Provider Reg Key

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 38 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
