# T1202-4: Indirect Command Execution

**MITRE ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202)
**Technique:** Indirect Command Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1202 -TestNumbers 4` — Indirect Command Execution - Scriptrunner.exe

## Telemetry (108 events)
- **Sysmon**: 56 events
- **Security**: 14 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
