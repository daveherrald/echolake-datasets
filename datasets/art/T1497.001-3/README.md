# T1497.001-3: System Checks

**MITRE ATT&CK:** [T1497.001](https://attack.mitre.org/techniques/T1497/001)
**Technique:** System Checks
**Tactic(s):** defense-evasion, discovery
**ART Test:** `Invoke-AtomicTest T1497.001 -TestNumbers 3` — Detect Virtualization Environment (Windows)

## Telemetry (85 events)
- **Sysmon**: 33 events
- **Security**: 12 events
- **Powershell**: 39 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
