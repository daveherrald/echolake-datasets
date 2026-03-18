# T1562.004-24: Disable or Modify System Firewall

**MITRE ATT&CK:** [T1562.004](https://attack.mitre.org/techniques/T1562/004)
**Technique:** Disable or Modify System Firewall
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.004 -TestNumbers 24` — Set a firewall rule using New-NetFirewallRule

## Telemetry (114 events)
- **Sysmon**: 60 events
- **Security**: 14 events
- **Powershell**: 39 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
