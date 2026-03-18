# T1562.006-13: Indicator Blocking

**MITRE ATT&CK:** [T1562.006](https://attack.mitre.org/techniques/T1562/006)
**Technique:** Indicator Blocking
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.006 -TestNumbers 13` — Disable .NET Event Tracing for Windows Via Environment Variable HKLM Registry - PowerShell

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
