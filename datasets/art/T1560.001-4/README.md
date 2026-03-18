# T1560.001-4: Archive via Utility

**MITRE ATT&CK:** [T1560.001](https://attack.mitre.org/techniques/T1560/001)
**Technique:** Archive via Utility
**Tactic(s):** collection
**ART Test:** `Invoke-AtomicTest T1560.001 -TestNumbers 4` — Compress Data and lock with password for Exfiltration with 7zip

## Telemetry (80 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
