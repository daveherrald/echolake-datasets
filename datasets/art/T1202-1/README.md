# T1202-1: Indirect Command Execution

**MITRE ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202)
**Technique:** Indirect Command Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1202 -TestNumbers 1` — Indirect Command Execution - pcalua.exe

## Telemetry (84 events)
- **Sysmon**: 32 events
- **Security**: 18 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
