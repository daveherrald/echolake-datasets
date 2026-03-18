# T1572-4: Protocol Tunneling

**MITRE ATT&CK:** [T1572](https://attack.mitre.org/techniques/T1572)
**Technique:** Protocol Tunneling
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1572 -TestNumbers 4` — run ngrok

## Telemetry (123 events)
- **Sysmon**: 46 events
- **Security**: 13 events
- **Powershell**: 64 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
