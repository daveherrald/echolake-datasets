# T1010-1: Application Window Discovery

**MITRE ATT&CK:** [T1010](https://attack.mitre.org/techniques/T1010)
**Technique:** Application Window Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1010 -TestNumbers 1` — List Process Main Windows - C# .NET

## Telemetry (85 events)
- **Sysmon**: 35 events
- **Security**: 16 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
