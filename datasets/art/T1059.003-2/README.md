# T1059.003-2: Windows Command Shell

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003)
**Technique:** Windows Command Shell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.003 -TestNumbers 2` — Writes text to a file and displays it.

## Telemetry (68 events)
- **Sysmon**: 23 events
- **Security**: 11 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
