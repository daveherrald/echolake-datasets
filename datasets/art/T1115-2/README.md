# T1115-2: Clipboard Data

**MITRE ATT&CK:** [T1115](https://attack.mitre.org/techniques/T1115)
**Technique:** Clipboard Data
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1115 -TestNumbers 2` — Execute Commands from Clipboard using PowerShell

## Telemetry (89 events)
- **Sysmon**: 27 events
- **Security**: 12 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
