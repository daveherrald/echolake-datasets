# T1202-3: Indirect Command Execution

**MITRE ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202)
**Technique:** Indirect Command Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1202 -TestNumbers 3` — Indirect Command Execution - conhost.exe

## Telemetry (81 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
