# T1562.002-9: Disable Windows Event Logging

**MITRE ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002)
**Technique:** Disable Windows Event Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.002 -TestNumbers 9` — Modify Event Log Channel Access Permissions via Registry 2 - PowerShell

## Telemetry (97 events)
- **Sysmon**: 42 events
- **Security**: 15 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
