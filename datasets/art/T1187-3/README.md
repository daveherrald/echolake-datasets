# T1187-3: Forced Authentication

**MITRE ATT&CK:** [T1187](https://attack.mitre.org/techniques/T1187)
**Technique:** Forced Authentication
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1187 -TestNumbers 3` — Trigger an authenticated RPC call to a target server with no Sign flag set

## Telemetry (74 events)
- **Sysmon**: 28 events
- **Security**: 15 events
- **Powershell**: 31 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
