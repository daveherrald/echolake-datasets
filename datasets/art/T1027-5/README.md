# T1027-5: Obfuscated Files or Information

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027)
**Technique:** Obfuscated Files or Information
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027 -TestNumbers 5` — DLP Evasion via Sensitive Data in VBA Macro over email

## Telemetry (74 events)
- **Sysmon**: 26 events
- **Security**: 11 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
