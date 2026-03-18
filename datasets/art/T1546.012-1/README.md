# T1546.012-1: Image File Execution Options Injection

**MITRE ATT&CK:** [T1546.012](https://attack.mitre.org/techniques/T1546/012)
**Technique:** Image File Execution Options Injection
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.012 -TestNumbers 1` — IFEO Add Debugger

## Telemetry (56 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
