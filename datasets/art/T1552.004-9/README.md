# T1552.004-9: Private Keys

**MITRE ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004)
**Technique:** Private Keys
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.004 -TestNumbers 9` — ADFS token signing and encryption certificates theft - Local

## Telemetry (110 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 52 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
