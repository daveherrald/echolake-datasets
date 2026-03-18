# T1572-1: Protocol Tunneling

**MITRE ATT&CK:** [T1572](https://attack.mitre.org/techniques/T1572)
**Technique:** Protocol Tunneling
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1572 -TestNumbers 1` — DNS over HTTPS Large Query Volume

## Telemetry (51 events)
- **Sysmon**: 1 events
- **Security**: 13 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
