# T1484.001-1: Group Policy Modification

**MITRE ATT&CK:** [T1484.001](https://attack.mitre.org/techniques/T1484/001)
**Technique:** Group Policy Modification
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1484.001 -TestNumbers 1` — LockBit Black - Modify Group policy settings -cmd

## Telemetry (97 events)
- **Sysmon**: 41 events
- **Security**: 22 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
