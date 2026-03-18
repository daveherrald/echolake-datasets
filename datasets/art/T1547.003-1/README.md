# T1547.003-1: Time Providers

**MITRE ATT&CK:** [T1547.003](https://attack.mitre.org/techniques/T1547/003)
**Technique:** Time Providers
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.003 -TestNumbers 1` — Create a new time provider

## Telemetry (129 events)
- **Sysmon**: 58 events
- **Security**: 27 events
- **Powershell**: 38 events
- **System**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
