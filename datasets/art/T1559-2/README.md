# T1559-2: Inter-Process Communication

**MITRE ATT&CK:** [T1559](https://attack.mitre.org/techniques/T1559)
**Technique:** Inter-Process Communication
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1559 -TestNumbers 2` — Cobalt Strike Lateral Movement (psexec_psh) pipe

## Telemetry (76 events)
- **Sysmon**: 32 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
