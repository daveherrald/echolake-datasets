# T1041-1: Exfiltration Over C2 Channel

**MITRE ATT&CK:** [T1041](https://attack.mitre.org/techniques/T1041)
**Technique:** Exfiltration Over C2 Channel
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1041 -TestNumbers 1` — C2 Data Exfiltration

## Telemetry (96 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
