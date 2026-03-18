# T1048-3: Exfiltration Over Alternative Protocol

**MITRE ATT&CK:** [T1048](https://attack.mitre.org/techniques/T1048)
**Technique:** Exfiltration Over Alternative Protocol
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1048 -TestNumbers 3` — DNSExfiltration (doh)

## Telemetry (89 events)
- **Sysmon**: 30 events
- **Security**: 10 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
