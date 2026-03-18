# T1071.004-1: DNS

**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004)
**Technique:** DNS
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1071.004 -TestNumbers 1` — DNS Large Query Volume

## Telemetry (1086 events)
- **Sysmon**: 1016 events
- **Security**: 24 events
- **Powershell**: 45 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
