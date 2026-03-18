# T1218.007-5: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 5` — WMI Win32_Product Class - Execute Local MSI file with embedded JScript

## Telemetry (100 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 49 events
- **Application**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
