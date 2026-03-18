# T1218.009-2: Regsvcs/Regasm

**MITRE ATT&CK:** [T1218.009](https://attack.mitre.org/techniques/T1218/009)
**Technique:** Regsvcs/Regasm
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.009 -TestNumbers 2` — Regsvcs Uninstall Method Call Test

## Telemetry (108 events)
- **Sysmon**: 53 events
- **Security**: 17 events
- **Powershell**: 37 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
