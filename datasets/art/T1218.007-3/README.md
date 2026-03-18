# T1218.007-3: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 3` — Msiexec.exe - Execute Local MSI file with an embedded DLL

## Telemetry (103 events)
- **Sysmon**: 38 events
- **Security**: 23 events
- **Powershell**: 36 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
