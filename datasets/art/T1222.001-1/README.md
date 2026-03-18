# T1222.001-1: Windows File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222.001](https://attack.mitre.org/techniques/T1222/001)
**Technique:** Windows File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222.001 -TestNumbers 1` — Take ownership using takeown utility

## Telemetry (73 events)
- **Sysmon**: 27 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
