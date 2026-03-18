# T1112-4: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 4` — Use Powershell to Modify registry to store logon credentials

## Telemetry (97 events)
- **Sysmon**: 47 events
- **Security**: 12 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
