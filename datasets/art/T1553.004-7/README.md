# T1553.004-7: Install Root Certificate

**MITRE ATT&CK:** [T1553.004](https://attack.mitre.org/techniques/T1553/004)
**Technique:** Install Root Certificate
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1553.004 -TestNumbers 7` — Add Root Certificate to CurrentUser Certificate Store

## Telemetry (122 events)
- **Sysmon**: 44 events
- **Security**: 12 events
- **Powershell**: 66 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
