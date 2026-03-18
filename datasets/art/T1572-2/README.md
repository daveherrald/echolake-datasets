# T1572-2: Protocol Tunneling

**MITRE ATT&CK:** [T1572](https://attack.mitre.org/techniques/T1572)
**Technique:** Protocol Tunneling
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1572 -TestNumbers 2` — DNS over HTTPS Regular Beaconing

## Telemetry (121 events)
- **Sysmon**: 40 events
- **Security**: 17 events
- **Powershell**: 62 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
