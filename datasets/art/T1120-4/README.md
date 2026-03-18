# T1120-4: Peripheral Device Discovery

**MITRE ATT&CK:** [T1120](https://attack.mitre.org/techniques/T1120)
**Technique:** Peripheral Device Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1120 -TestNumbers 4` — Get Printer Device List via PowerShell Command

## Telemetry (82 events)
- **Sysmon**: 35 events
- **Security**: 9 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
