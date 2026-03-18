# T1135-12: Network Share Discovery

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135)
**Technique:** Network Share Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1135 -TestNumbers 12` — Enumerate All Network Shares with Snaffler

## Telemetry (126 events)
- **Sysmon**: 53 events
- **Security**: 23 events
- **Powershell**: 48 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
