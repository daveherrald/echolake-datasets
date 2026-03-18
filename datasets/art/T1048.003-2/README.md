# T1048.003-2: Exfiltration Over Unencrypted Non-C2 Protocol

**MITRE ATT&CK:** [T1048.003](https://attack.mitre.org/techniques/T1048/003)
**Technique:** Exfiltration Over Unencrypted Non-C2 Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048.003 -TestNumbers 2` — Exfiltration Over Alternative Protocol - ICMP

## Telemetry (106 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
