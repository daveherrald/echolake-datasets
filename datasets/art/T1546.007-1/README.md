# T1546.007-1: Netsh Helper DLL

**MITRE ATT&CK:** [T1546.007](https://attack.mitre.org/techniques/T1546/007)
**Technique:** Netsh Helper DLL
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.007 -TestNumbers 1` — Netsh Helper DLL Registration

## Telemetry (85 events)
- **Sysmon**: 33 events
- **Security**: 18 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
