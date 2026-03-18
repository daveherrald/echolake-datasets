# T1491.001-3: Internal Defacement

**MITRE ATT&CK:** [T1491.001](https://attack.mitre.org/techniques/T1491/001)
**Technique:** Internal Defacement
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1491.001 -TestNumbers 3` — ESXi - Change Welcome Message on Direct Console User Interface (DCUI)

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
