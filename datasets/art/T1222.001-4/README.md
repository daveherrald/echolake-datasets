# T1222.001-4: Windows File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222.001](https://attack.mitre.org/techniques/T1222/001)
**Technique:** Windows File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222.001 -TestNumbers 4` — attrib - hide file

## Telemetry (66 events)
- **Sysmon**: 20 events
- **Security**: 14 events
- **Powershell**: 32 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
