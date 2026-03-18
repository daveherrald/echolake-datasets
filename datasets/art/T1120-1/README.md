# T1120-1: Peripheral Device Discovery

**MITRE ATT&CK:** [T1120](https://attack.mitre.org/techniques/T1120)
**Technique:** Peripheral Device Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1120 -TestNumbers 1` — Win32_PnPEntity Hardware Inventory

## Telemetry (90 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
