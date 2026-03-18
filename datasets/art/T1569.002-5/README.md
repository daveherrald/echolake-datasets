# T1569.002-5: Service Execution

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002)
**Technique:** Service Execution
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1569.002 -TestNumbers 5` — Use RemCom to execute a command on a remote host

## Telemetry (104 events)
- **Sysmon**: 46 events
- **Security**: 19 events
- **Powershell**: 35 events
- **Taskscheduler**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
