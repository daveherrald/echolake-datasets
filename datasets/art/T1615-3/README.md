# T1615-3: Group Policy Discovery

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615)
**Technique:** Group Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1615 -TestNumbers 3` — WinPwn - GPOAudit

## Telemetry (109 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
