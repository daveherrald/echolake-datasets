# T1505.002-1: Transport Agent

**MITRE ATT&CK:** [T1505.002](https://attack.mitre.org/techniques/T1505/002)
**Technique:** Transport Agent
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1505.002 -TestNumbers 1` — Install MS Exchange Transport Agent Persistence

## Telemetry (106 events)
- **Sysmon**: 42 events
- **Security**: 11 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
