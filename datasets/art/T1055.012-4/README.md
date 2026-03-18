# T1055.012-4: Process Hollowing

**MITRE ATT&CK:** [T1055.012](https://attack.mitre.org/techniques/T1055/012)
**Technique:** Process Hollowing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.012 -TestNumbers 4` — Process Hollowing in Go using CreateProcessW and CreatePipe WinAPIs (T1055.012)

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
