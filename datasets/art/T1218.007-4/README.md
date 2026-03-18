# T1218.007-4: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 4` — Msiexec.exe - Execute Local MSI file with an embedded EXE

## Telemetry (100 events)
- **Sysmon**: 39 events
- **Security**: 21 events
- **Powershell**: 34 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
