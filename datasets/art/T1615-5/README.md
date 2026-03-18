# T1615-5: Group Policy Discovery

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615)
**Technique:** Group Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1615 -TestNumbers 5` — MSFT Get-GPO Cmdlet

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
