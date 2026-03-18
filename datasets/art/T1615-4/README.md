# T1615-4: Group Policy Discovery

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615)
**Technique:** Group Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1615 -TestNumbers 4` — WinPwn - GPORemoteAccessPolicy

## Telemetry (89 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 52 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
