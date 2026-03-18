# T1129-1: Shared Modules

**MITRE ATT&CK:** [T1129](https://attack.mitre.org/techniques/T1129)
**Technique:** Shared Modules
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1129 -TestNumbers 1` — ESXi - Install a custom VIB on an ESXi host

## Telemetry (74 events)
- **Sysmon**: 27 events
- **Security**: 12 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
