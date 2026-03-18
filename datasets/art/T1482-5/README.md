# T1482-5: Domain Trust Discovery

**MITRE ATT&CK:** [T1482](https://attack.mitre.org/techniques/T1482)
**Technique:** Domain Trust Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1482 -TestNumbers 5` — Adfind - Enumerate Active Directory Trusts

## Telemetry (86 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
