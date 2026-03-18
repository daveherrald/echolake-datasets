# T1491.001-4: Internal Defacement

**MITRE ATT&CK:** [T1491.001](https://attack.mitre.org/techniques/T1491/001)
**Technique:** Internal Defacement
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1491.001 -TestNumbers 4` — Windows - Display a simulated ransom note via Notepad (non-destructive)

## Telemetry (92 events)
- **Sysmon**: 40 events
- **Security**: 11 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
