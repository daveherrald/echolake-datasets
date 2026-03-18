# T1570-2: Lateral Tool Transfer

**MITRE ATT&CK:** [T1570](https://attack.mitre.org/techniques/T1570)
**Technique:** Lateral Tool Transfer
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1570 -TestNumbers 2` — Exfiltration Over SMB over QUIC (NET USE)

## Telemetry (104 events)
- **Sysmon**: 41 events
- **Security**: 16 events
- **Powershell**: 46 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
