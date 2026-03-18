# T1056.001-1: Keylogging

**MITRE ATT&CK:** [T1056.001](https://attack.mitre.org/techniques/T1056/001)
**Technique:** Keylogging
**Tactic(s):** collection, credential-access
**ART Test:** `Invoke-AtomicTest T1056.001 -TestNumbers 1` — Input Capture

## Telemetry (83 events)
- **Sysmon**: 35 events
- **Security**: 11 events
- **Powershell**: 35 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
