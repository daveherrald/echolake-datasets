# T1556.002-1: Password Filter DLL

**MITRE ATT&CK:** [T1556.002](https://attack.mitre.org/techniques/T1556/002)
**Technique:** Password Filter DLL
**Tactic(s):** credential-access, defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1556.002 -TestNumbers 1` — Install and Register Password Filter DLL

## Telemetry (127 events)
- **Sysmon**: 45 events
- **Security**: 19 events
- **Powershell**: 61 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
