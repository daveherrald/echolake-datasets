# T1027-2: Obfuscated Files or Information

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027)
**Technique:** Obfuscated Files or Information
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027 -TestNumbers 2` — Execute base64-encoded PowerShell

## Telemetry (93 events)
- **Sysmon**: 39 events
- **Security**: 14 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
