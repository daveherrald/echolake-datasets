# T1546.002-1: Screensaver

**MITRE ATT&CK:** [T1546.002](https://attack.mitre.org/techniques/T1546/002)
**Technique:** Screensaver
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.002 -TestNumbers 1` — Set Arbitrary Binary as Screensaver

## Telemetry (107 events)
- **Sysmon**: 45 events
- **Security**: 20 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
