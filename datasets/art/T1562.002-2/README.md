# T1562.002-2: Disable Windows Event Logging

**MITRE ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002)
**Technique:** Disable Windows Event Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.002 -TestNumbers 2` — Disable Windows IIS HTTP Logging via PowerShell

## Telemetry (102 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
