# T1552.001-4: Credentials In Files

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)
**Technique:** Credentials In Files
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.001 -TestNumbers 4` — Extracting passwords with findstr

## Telemetry (11273 events)
- **Sysmon**: 28 events
- **Security**: 16 events
- **Powershell**: 11227 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
