# T1562.010-2: Downgrade Attack

**MITRE ATT&CK:** [T1562.010](https://attack.mitre.org/techniques/T1562/010)
**Technique:** Downgrade Attack
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.010 -TestNumbers 2` — ESXi - Change VIB acceptance level to CommunitySupported via ESXCLI

## Telemetry (62 events)
- **Sysmon**: 17 events
- **Security**: 12 events
- **Powershell**: 33 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
