# T1552.004-10: Private Keys

**MITRE ATT&CK:** [T1552.004](https://attack.mitre.org/techniques/T1552/004)
**Technique:** Private Keys
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.004 -TestNumbers 10` — ADFS token signing and encryption certificates theft - Remote

## Telemetry (139 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 93 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
