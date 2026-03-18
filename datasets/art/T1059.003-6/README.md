# T1059.003-6: Windows Command Shell

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003)
**Technique:** Windows Command Shell
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1059.003 -TestNumbers 6` — Command prompt writing script to file then executes it

## Telemetry (88 events)
- **Sysmon**: 37 events
- **Security**: 17 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
