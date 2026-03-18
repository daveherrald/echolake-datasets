# T1036-1: Masquerading

**MITRE ATT&CK:** [T1036](https://attack.mitre.org/techniques/T1036)
**Technique:** Masquerading
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036 -TestNumbers 1` — System File Copied to Unusual Location

## Telemetry (89 events)
- **Sysmon**: 32 events
- **Security**: 17 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
