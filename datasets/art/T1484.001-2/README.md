# T1484.001-2: Group Policy Modification

**MITRE ATT&CK:** [T1484.001](https://attack.mitre.org/techniques/T1484/001)
**Technique:** Group Policy Modification
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1484.001 -TestNumbers 2` — LockBit Black - Modify Group policy settings -Powershell

## Telemetry (99 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 43 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
