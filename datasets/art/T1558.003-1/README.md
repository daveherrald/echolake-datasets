# T1558.003-1: Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
**Technique:** Kerberoasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.003 -TestNumbers 1` — Request for service tickets

## Telemetry (97 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
