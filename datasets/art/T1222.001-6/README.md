# T1222.001-6: Windows File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222.001](https://attack.mitre.org/techniques/T1222/001)
**Technique:** Windows File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222.001 -TestNumbers 6` — SubInAcl Execution

## Telemetry (52 events)
- **Sysmon**: 16 events
- **Security**: 10 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
