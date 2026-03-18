# T1562.002-5: Disable Windows Event Logging

**MITRE ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002)
**Technique:** Disable Windows Event Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.002 -TestNumbers 5` — Clear Windows Audit Policy Config

## Telemetry (93 events)
- **Sysmon**: 30 events
- **Security**: 29 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
