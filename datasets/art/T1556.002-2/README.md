# T1556.002-2: Password Filter DLL

**MITRE ATT&CK:** [T1556.002](https://attack.mitre.org/techniques/T1556/002)
**Technique:** Password Filter DLL
**Tactic(s):** credential-access, defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1556.002 -TestNumbers 2` — Install Additional Authentication Packages

## Telemetry (152 events)
- **Sysmon**: 55 events
- **Security**: 34 events
- **Powershell**: 61 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
