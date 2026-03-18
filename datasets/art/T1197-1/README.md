# T1197-1: BITS Jobs

**MITRE ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197)
**Technique:** BITS Jobs
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1197 -TestNumbers 1` — Bitsadmin Download (cmd)

## Telemetry (79 events)
- **Sysmon**: 31 events
- **Security**: 12 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
