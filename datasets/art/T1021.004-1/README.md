# T1021.004-1: SSH

**MITRE ATT&CK:** [T1021.004](https://attack.mitre.org/techniques/T1021/004)
**Technique:** SSH
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.004 -TestNumbers 1` — ESXi - Enable SSH via PowerCLI

## Telemetry (100 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
