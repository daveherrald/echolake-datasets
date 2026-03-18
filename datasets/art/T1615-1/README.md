# T1615-1: Group Policy Discovery

**MITRE ATT&CK:** [T1615](https://attack.mitre.org/techniques/T1615)
**Technique:** Group Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1615 -TestNumbers 1` — Display group policy information via gpresult

## Telemetry (74 events)
- **Sysmon**: 28 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
