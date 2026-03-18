# T1202-2: Indirect Command Execution

**MITRE ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202)
**Technique:** Indirect Command Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1202 -TestNumbers 2` — Indirect Command Execution - forfiles.exe

## Telemetry (77 events)
- **Sysmon**: 28 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
