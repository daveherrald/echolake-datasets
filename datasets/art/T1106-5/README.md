# T1106-5: Native API

**MITRE ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106)
**Technique:** Native API
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1106 -TestNumbers 5` — Run Shellcode via Syscall in Go

## Telemetry (77 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
