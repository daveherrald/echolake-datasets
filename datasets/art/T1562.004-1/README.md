# T1562.004-1: Disable or Modify System Firewall

**MITRE ATT&CK:** [T1562.004](https://attack.mitre.org/techniques/T1562/004)
**Technique:** Disable or Modify System Firewall
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.004 -TestNumbers 1` — Disable Microsoft Defender Firewall

## Telemetry (149 events)
- **Sysmon**: 84 events
- **Security**: 20 events
- **Powershell**: 34 events
- **Application**: 1 events
- **Wmi**: 1 events
- **Taskscheduler**: 9 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
