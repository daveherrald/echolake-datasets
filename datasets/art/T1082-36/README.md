# T1082-36: System Information Discovery

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082)
**Technique:** System Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1082 -TestNumbers 36` — Display volume shadow copies with "vssadmin"

## Telemetry (99 events)
- **Sysmon**: 41 events
- **Security**: 24 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
