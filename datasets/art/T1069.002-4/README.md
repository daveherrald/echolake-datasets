# T1069.002-4: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 4` — Find machines where user has local admin access (PowerView)

## Telemetry (77 events)
- **Sysmon**: 27 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
