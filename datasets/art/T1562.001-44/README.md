# T1562.001-44: Disable or Modify Tools

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001)
**Technique:** Disable or Modify Tools
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.001 -TestNumbers 44` — Disable Hypervisor-Enforced Code Integrity (HVCI)

## Telemetry (101 events)
- **Sysmon**: 48 events
- **Security**: 12 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
