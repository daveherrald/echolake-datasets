# T1559-4: Inter-Process Communication

**MITRE ATT&CK:** [T1559](https://attack.mitre.org/techniques/T1559)
**Technique:** Inter-Process Communication
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1559 -TestNumbers 4` — Cobalt Strike post-exploitation pipe (4.2 and later)

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
