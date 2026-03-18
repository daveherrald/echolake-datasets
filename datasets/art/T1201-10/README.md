# T1201-10: Password Policy Discovery

**MITRE ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201)
**Technique:** Password Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1201 -TestNumbers 10` — Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
