# T1218.007-11: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 11` — Msiexec.exe - Execute Remote MSI file

## Telemetry (103 events)
- **Sysmon**: 40 events
- **Security**: 21 events
- **Powershell**: 36 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
