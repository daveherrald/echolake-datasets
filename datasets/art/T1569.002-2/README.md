# T1569.002-2: Service Execution

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002)
**Technique:** Service Execution
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1569.002 -TestNumbers 2` — Use PsExec to execute a command on a remote host

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
