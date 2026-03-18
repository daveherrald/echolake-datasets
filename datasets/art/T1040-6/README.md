# T1040-6: Network Sniffing

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040)
**Technique:** Network Sniffing
**Tactic(s):** credential-access, discovery
**ART Test:** `Invoke-AtomicTest T1040 -TestNumbers 6` — Windows Internal pktmon capture

## Telemetry (102 events)
- **Sysmon**: 47 events
- **Security**: 21 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
