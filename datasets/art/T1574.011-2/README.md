# T1574.011-2: Services Registry Permissions Weakness

**MITRE ATT&CK:** [T1574.011](https://attack.mitre.org/techniques/T1574/011)
**Technique:** Services Registry Permissions Weakness
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.011 -TestNumbers 2` — Service ImagePath Change with reg.exe

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 13 events
- **Powershell**: 34 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
