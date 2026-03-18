# T1070.008-1: Clear Mailbox Data

**MITRE ATT&CK:** [T1070.008](https://attack.mitre.org/techniques/T1070/008)
**Technique:** Clear Mailbox Data
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.008 -TestNumbers 1` — Copy and Delete Mailbox Data on Windows

## Telemetry (90 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 41 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
