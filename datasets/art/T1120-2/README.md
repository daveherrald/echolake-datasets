# T1120-2: Peripheral Device Discovery

**MITRE ATT&CK:** [T1120](https://attack.mitre.org/techniques/T1120)
**Technique:** Peripheral Device Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1120 -TestNumbers 2` — WinPwn - printercheck

## Telemetry (125 events)
- **Sysmon**: 50 events
- **Security**: 12 events
- **Powershell**: 63 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
