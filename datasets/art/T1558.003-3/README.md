# T1558.003-3: Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
**Technique:** Kerberoasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.003 -TestNumbers 3` — Extract all accounts in use as SPN using setspn

## Telemetry (65 events)
- **Sysmon**: 19 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
