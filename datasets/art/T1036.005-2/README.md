# T1036.005-2: Match Legitimate Resource Name or Location

**MITRE ATT&CK:** [T1036.005](https://attack.mitre.org/techniques/T1036/005)
**Technique:** Match Legitimate Resource Name or Location
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.005 -TestNumbers 2` — Masquerade as a built-in system executable

## Telemetry (135 events)
- **Sysmon**: 73 events
- **Security**: 23 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
