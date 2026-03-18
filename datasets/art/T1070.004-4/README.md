# T1070.004-4: File Deletion

**MITRE ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004)
**Technique:** File Deletion
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.004 -TestNumbers 4` — Delete a single file - Windows cmd

## Telemetry (52 events, noise-filtered)
- **Powershell**: 26 events
- **Security**: 10 events
- **Sysmon**: 16 events

## Pipeline
Events from ACME-WS02 via Cribl Edge.
Infrastructure noise filtered (qemu-ga, Cribl, NSSM, ART framework overhead).
