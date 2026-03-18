# T1048.003-6: Exfiltration Over Unencrypted Non-C2 Protocol

**MITRE ATT&CK:** [T1048.003](https://attack.mitre.org/techniques/T1048/003)
**Technique:** Exfiltration Over Unencrypted Non-C2 Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048.003 -TestNumbers 6` — MAZE FTP Upload

## Telemetry (86 events)
- **Sysmon**: 32 events
- **Security**: 12 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
