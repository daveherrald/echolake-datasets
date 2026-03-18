# T1003.004-2: LSA Secrets

**MITRE ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004)
**Technique:** LSA Secrets
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.004 -TestNumbers 2` — Dump Kerberos Tickets from LSA using dumper.ps1

## Telemetry (104 events)
- **Sysmon**: 42 events
- **Security**: 11 events
- **Powershell**: 47 events
- **Taskscheduler**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
