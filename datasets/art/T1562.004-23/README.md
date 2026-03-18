# T1562.004-23: Disable or Modify System Firewall

**MITRE ATT&CK:** [T1562.004](https://attack.mitre.org/techniques/T1562/004)
**Technique:** Disable or Modify System Firewall
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.004 -TestNumbers 23` — ESXi - Disable Firewall via Esxcli

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
