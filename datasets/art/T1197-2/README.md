# T1197-2: BITS Jobs

**MITRE ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197)
**Technique:** BITS Jobs
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1197 -TestNumbers 2` — Bitsadmin Download (PowerShell)

## Telemetry (111 events)
- **Sysmon**: 53 events
- **Security**: 19 events
- **Powershell**: 37 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
