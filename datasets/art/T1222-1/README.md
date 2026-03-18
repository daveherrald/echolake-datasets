# T1222-1: File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222](https://attack.mitre.org/techniques/T1222)
**Technique:** File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222 -TestNumbers 1` — Enable Local and Remote Symbolic Links via fsutil

## Telemetry (59 events)
- **Sysmon**: 18 events
- **Security**: 15 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
