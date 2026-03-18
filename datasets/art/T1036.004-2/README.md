# T1036.004-2: Masquerade Task or Service

**MITRE ATT&CK:** [T1036.004](https://attack.mitre.org/techniques/T1036/004)
**Technique:** Masquerade Task or Service
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.004 -TestNumbers 2` — Creating W32Time similar named service using sc

## Telemetry (91 events)
- **Sysmon**: 41 events
- **Security**: 14 events
- **Powershell**: 35 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
