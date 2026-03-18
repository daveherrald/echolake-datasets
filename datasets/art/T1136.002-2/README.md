# T1136.002-2: Domain Account

**MITRE ATT&CK:** [T1136.002](https://attack.mitre.org/techniques/T1136/002)
**Technique:** Domain Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.002 -TestNumbers 2` — Create a new account similar to ANONYMOUS LOGON

## Telemetry (83 events)
- **Sysmon**: 34 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
