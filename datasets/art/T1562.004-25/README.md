# T1562.004-25: Disable or Modify System Firewall

**MITRE ATT&CK:** [T1562.004](https://attack.mitre.org/techniques/T1562/004)
**Technique:** Disable or Modify System Firewall
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.004 -TestNumbers 25` — ESXi - Set Firewall to PASS Traffic

## Telemetry (75 events)
- **Sysmon**: 27 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
