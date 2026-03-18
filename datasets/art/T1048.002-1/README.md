# T1048.002-1: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

**MITRE ATT&CK:** [T1048.002](https://attack.mitre.org/techniques/T1048/002)
**Technique:** Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048.002 -TestNumbers 1` — Exfiltrate data HTTPS using curl windows

## Telemetry (73 events)
- **Sysmon**: 27 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
