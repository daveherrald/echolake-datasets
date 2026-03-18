# T1558.003-2: Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
**Technique:** Kerberoasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.003 -TestNumbers 2` — Rubeus kerberoast

## Telemetry (82 events)
- **Sysmon**: 31 events
- **Security**: 14 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
