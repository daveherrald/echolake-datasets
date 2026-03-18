# T1082-37: System Information Discovery

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082)
**Technique:** System Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1082 -TestNumbers 37` — Identify System Locale and Regional Settings with PowerShell

## Telemetry (96 events)
- **Sysmon**: 40 events
- **Security**: 19 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
