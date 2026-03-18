# T1055.012-3: Process Hollowing

**MITRE ATT&CK:** [T1055.012](https://attack.mitre.org/techniques/T1055/012)
**Technique:** Process Hollowing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.012 -TestNumbers 3` — Process Hollowing in Go using CreateProcessW WinAPI

## Telemetry (101 events)
- **Sysmon**: 45 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
