# T1137.001-1: Office Template Macros

**MITRE ATT&CK:** [T1137.001](https://attack.mitre.org/techniques/T1137/001)
**Technique:** Office Template Macros
**Tactic(s):** persistence
**ART Test:** `Invoke-AtomicTest T1137.001 -TestNumbers 1` — Injecting a Macro into the Word Normal.dotm Template for Persistence via PowerShell

## Telemetry (176 events)
- **Sysmon**: 46 events
- **Security**: 11 events
- **Powershell**: 119 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
