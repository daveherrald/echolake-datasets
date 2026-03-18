# T1059.003-5: Windows Command Shell

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003)
**Technique:** Windows Command Shell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.003 -TestNumbers 5` — Command Prompt read contents from CMD file and execute

## Telemetry (75 events)
- **Sysmon**: 23 events
- **Security**: 18 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
