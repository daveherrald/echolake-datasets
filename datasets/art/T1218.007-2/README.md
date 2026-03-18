# T1218.007-2: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 2` — Msiexec.exe - Execute Local MSI file with embedded VBScript

## Telemetry (107 events)
- **Sysmon**: 42 events
- **Security**: 23 events
- **Powershell**: 36 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
