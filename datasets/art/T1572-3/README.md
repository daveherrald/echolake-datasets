# T1572-3: Protocol Tunneling

**MITRE ATT&CK:** [T1572](https://attack.mitre.org/techniques/T1572)
**Technique:** Protocol Tunneling
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1572 -TestNumbers 3` — DNS over HTTPS Long Domain Query

## Telemetry (49 events)
- **Sysmon**: 1 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
