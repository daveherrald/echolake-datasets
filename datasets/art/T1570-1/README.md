# T1570-1: Lateral Tool Transfer

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570)
**Technique:** Lateral Tool Transfer
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1570 -TestNumbers 1` — Exfiltration Over SMB over QUIC (New-SmbMapping)

## Telemetry (78 events)
- **Sysmon**: 2 events
- **Security**: 12 events
- **Powershell**: 63 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
