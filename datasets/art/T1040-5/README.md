# T1040-5: Network Sniffing

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040)
**Technique:** Network Sniffing
**Tactic(s):** credential-access, discovery
**ART Test:** `Invoke-AtomicTest T1040 -TestNumbers 5` — Windows Internal Packet Capture

## Telemetry (64 events)
- **Sysmon**: 22 events
- **Security**: 16 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
