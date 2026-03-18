# T1222.001-5: Windows File and Directory Permissions Modification

**MITRE ATT&CK:** [T1222.001](https://attack.mitre.org/techniques/T1222/001)
**Technique:** Windows File and Directory Permissions Modification
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1222.001 -TestNumbers 5` — Grant Full Access to folder for Everyone - Ryuk Ransomware Style

## Telemetry (65 events)
- **Sysmon**: 17 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
