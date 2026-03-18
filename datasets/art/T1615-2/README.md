# T1615-2: Group Policy Discovery

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615)
**Technique:** Group Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1615 -TestNumbers 2` — Get-DomainGPO to display group policy information via PowerView

## Telemetry (59 events)
- **Sysmon**: 4 events
- **Security**: 7 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
