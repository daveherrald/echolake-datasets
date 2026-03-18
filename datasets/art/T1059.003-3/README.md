# T1059.003-3: Windows Command Shell

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003)
**Technique:** Windows Command Shell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.003 -TestNumbers 3` — Suspicious Execution via Windows Command Shell

## Telemetry (64 events)
- **Sysmon**: 18 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
