# T1547.003-2: Time Providers

**MITRE ATT&CK:** [T1547.003](https://attack.mitre.org/techniques/T1547/003)
**Technique:** Time Providers
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.003 -TestNumbers 2` — Edit an existing time provider

## Telemetry (116 events)
- **Sysmon**: 48 events
- **Security**: 26 events
- **Powershell**: 38 events
- **System**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
