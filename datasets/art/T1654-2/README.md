# T1654-2: Log Enumeration

**MITRE ATT&CK:** [T1654](https://attack.mitre.org/techniques/T1654)
**Technique:** Log Enumeration
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1654 -TestNumbers 2` — Enumerate Windows Security Log via WevtUtil

## Telemetry (97 events)
- **Sysmon**: 37 events
- **Security**: 16 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
