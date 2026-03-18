# T1559-3: Inter-Process Communication

**MITRE ATT&CK:** [T1559](https://attack.mitre.org/techniques/T1559)
**Technique:** Inter-Process Communication
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1559 -TestNumbers 3` — Cobalt Strike SSH (postex_ssh) pipe

## Telemetry (88 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
