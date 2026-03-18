# T1027-3: Obfuscated Files or Information

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027)
**Technique:** Obfuscated Files or Information
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027 -TestNumbers 3` — Execute base64-encoded PowerShell from Windows Registry

## Telemetry (103 events)
- **Sysmon**: 49 events
- **Security**: 13 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
