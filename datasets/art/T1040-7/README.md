# T1040-7: Network Sniffing

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040)
**Technique:** Network Sniffing
**Tactic(s):** credential-access, discovery
**ART Test:** `Invoke-AtomicTest T1040 -TestNumbers 7` — Windows Internal pktmon set filter

## Telemetry (14889 events)
- **Sysmon**: 4832 events
- **Security**: 2300 events
- **Powershell**: 7712 events
- **System**: 20 events
- **Application**: 8 events
- **Wmi**: 7 events
- **Taskscheduler**: 10 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
