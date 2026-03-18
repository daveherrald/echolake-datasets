# T1136.002-3: Domain Account

**MITRE ATT&CK:** [T1136.002](https://attack.mitre.org/techniques/T1136/002)
**Technique:** Domain Account
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1136.002 -TestNumbers 3` — Create a new Domain Account using PowerShell

## Telemetry (97 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
