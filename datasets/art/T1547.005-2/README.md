# T1547.005-2: Security Support Provider

**MITRE ATT&CK:** [T1547.005](https://attack.mitre.org/techniques/T1547/005)
**Technique:** Security Support Provider
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.005 -TestNumbers 2` — Modify HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig Security Support Provider configuration in registry

## Telemetry (92 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 56 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
