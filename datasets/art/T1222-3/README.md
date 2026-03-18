# T1222-3: File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222](https://attack.mitre.org/techniques/T1222)
**Technique:** File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222 -TestNumbers 3` — Enable Local and Remote Symbolic Links via Powershell

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
