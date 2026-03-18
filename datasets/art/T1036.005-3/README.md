# T1036.005-3: Match Legitimate Resource Name or Location

**MITRE ATT&CK:** [T1036.005](https://attack.mitre.org/techniques/T1036/005)
**Technique:** Match Legitimate Resource Name or Location
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.005 -TestNumbers 3` — Masquerading cmd.exe as VEDetector.exe

## Telemetry (98 events)
- **Sysmon**: 43 events
- **Security**: 14 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
