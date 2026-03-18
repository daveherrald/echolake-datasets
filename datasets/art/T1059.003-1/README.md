# T1059.003-1: Windows Command Shell

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003)
**Technique:** Windows Command Shell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.003 -TestNumbers 1` — Create and Execute Batch Script

## Telemetry (92 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
