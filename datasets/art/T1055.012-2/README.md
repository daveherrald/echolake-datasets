# T1055.012-2: Process Hollowing

**MITRE ATT&CK:** [T1055.012](https://attack.mitre.org/techniques/T1055/012)
**Technique:** Process Hollowing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.012 -TestNumbers 2` — RunPE via VBA

## Telemetry (147 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 91 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
