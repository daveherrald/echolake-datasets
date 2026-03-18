# T1048.003-4: Exfiltration Over Unencrypted Non-C2 Protocol

**MITRE ATT&CK:** [T1048.003](https://attack.mitre.org/techniques/T1048/003)
**Technique:** Exfiltration Over Unencrypted Non-C2 Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048.003 -TestNumbers 4` — Exfiltration Over Alternative Protocol - HTTP

## Telemetry (94 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
