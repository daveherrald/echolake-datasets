# T1547.005-1: Security Support Provider

**MITRE ATT&CK:** [T1547.005](https://attack.mitre.org/techniques/T1547/005)
**Technique:** Security Support Provider
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.005 -TestNumbers 1` — Modify HKLM:\System\CurrentControlSet\Control\Lsa Security Support Provider configuration in registry

## Telemetry (85 events)
- **Sysmon**: 35 events
- **Security**: 10 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
