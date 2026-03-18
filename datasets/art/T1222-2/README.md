# T1222-2: File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222](https://attack.mitre.org/techniques/T1222)
**Technique:** File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222 -TestNumbers 2` — Enable Local and Remote Symbolic Links via reg.exe

## Telemetry (86 events)
- **Sysmon**: 38 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
