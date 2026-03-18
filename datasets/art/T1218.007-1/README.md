# T1218.007-1: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 1` — Msiexec.exe - Execute Local MSI file with embedded JScript

## Telemetry (78 events)
- **Sysmon**: 19 events
- **Security**: 23 events
- **Powershell**: 34 events
- **Application**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
