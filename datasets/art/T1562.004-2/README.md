# T1562.004-2: Disable or Modify System Firewall

**MITRE ATT&CK:** [T1562.004](https://attack.mitre.org/techniques/T1562/004)
**Technique:** Disable or Modify System Firewall
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.004 -TestNumbers 2` — Disable Microsoft Defender Firewall via Registry

## Telemetry (87 events)
- **Sysmon**: 38 events
- **Security**: 13 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
