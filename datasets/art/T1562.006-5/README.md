# T1562.006-5: Indicator Blocking

**MITRE ATT&CK:** [T1562.006](https://attack.mitre.org/techniques/T1562/006)
**Technique:** Indicator Blocking
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.006 -TestNumbers 5` — Disable Powershell ETW Provider - Windows

## Telemetry (78 events)
- **Sysmon**: 29 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
