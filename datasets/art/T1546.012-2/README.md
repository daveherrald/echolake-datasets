# T1546.012-2: Image File Execution Options Injection

**MITRE ATT&CK:** [T1546.012](https://attack.mitre.org/techniques/T1546/012)
**Technique:** Image File Execution Options Injection
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.012 -TestNumbers 2` — IFEO Global Flags

## Telemetry (93 events)
- **Sysmon**: 42 events
- **Security**: 16 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
