# T1115-4: Clipboard Data

**MITRE ATT&CK:** [T1115](https://attack.mitre.org/techniques/T1115)
**Technique:** Clipboard Data
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1115 -TestNumbers 4` — Collect Clipboard Data via VBA

## Telemetry (141 events)
- **Sysmon**: 39 events
- **Security**: 11 events
- **Powershell**: 91 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
