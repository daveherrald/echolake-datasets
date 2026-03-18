# T1048.003-5: Exfiltration Over Unencrypted Non-C2 Protocol

**MITRE ATT&CK:** [T1048.003](https://attack.mitre.org/techniques/T1048/003)
**Technique:** Exfiltration Over Unencrypted Non-C2 Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048.003 -TestNumbers 5` — Exfiltration Over Alternative Protocol - SMTP

## Telemetry (115 events)
- **Sysmon**: 51 events
- **Security**: 14 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
