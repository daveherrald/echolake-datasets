# T1087.002-1: Domain Account

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)
**Technique:** Domain Account
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1087.002 -TestNumbers 1` — Enumerate all accounts (Domain)

## Telemetry (96 events)
- **Sysmon**: 40 events
- **Security**: 19 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
