# T1003.002-2: Security Account Manager — Registry parse with pypykatz

## Technique Context

T1003.002 targets the Security Account Manager (SAM) database to extract local account NTLM hashes. Pypykatz is a pure-Python reimplementation of Mimikatz that can parse credential material directly from a running system or from offline hive dumps. The `live lsa` subcommand instructs pypykatz to access the live Local Security Authority subsystem and extract credential information from the running system — functionally equivalent to the in-memory credential dump operations performed by Mimikatz, but implemented in Python.

This technique is notable because it can operate without loading a native Windows DLL into sensitive processes. Pypykatz can be packaged as a standalone executable or run through Python, and its output format is identical to Mimikatz output that many incident responders are familiar with. Detection focuses on the pypykatz executable or Python interpreter accessing LSASS memory, process creation patterns, and the presence of pypykatz files in the filesystem.

The distinction from T1003.002-1 is the mechanism: rather than using `reg.exe` to export registry hives, pypykatz performs a live credential extraction from the running LSA subsystem. This means the attack surface is LSASS memory access rather than registry file writes.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Sysmon channel (19 events: 9x EID 11, 4x EID 1, 4x EID 10, 1x EID 17, 1x EID 7):** The most significant EID 1 event shows the pypykatz invocation directly: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1003_002\Scripts\pypykatz" live lsa`. The binary path `C:\AtomicRedTeam\ExternalPayloads\venv_t1003_002\Scripts\pypykatz` is the pre-staged pypykatz executable from the ART external payload. The `live lsa` arguments confirm this is a live credential extraction from the running LSA. EID 10 events show `powershell.exe` opening `whoami.exe` and `cmd.exe` with `0x1FFFFF` access — the standard ART test framework child spawning pattern. The file creation events in EID 11 are dominated by background system activity.

**Security channel (4 events, all EID 4688):** The four process creation events confirm `powershell.exe` (PID 0x1450) spawning `whoami.exe` (0x1214) pre-check, `cmd.exe` (0x17e4) for the pypykatz execution, `whoami.exe` (0xe34) post-check, and `cmd.exe` (0xdd0) for cleanup. The absence of EID 5379 (credential manager reads) in this dataset compared to the defended version is notable — the defended run showed 7 such events while this undefended run shows none in the sample window, suggesting different timing of background credential manager activity.

**PowerShell channel (104 events: 102x EID 4104, 2x EID 4103):** The ART test framework events are present — Import-Module and the standard runtime stubs. The EID 4103 module logging events indicate the ART module's exported functions were invoked.

**Compared to the defended dataset (sysmon: 35, security: 10, powershell: 34):** The undefended run has significantly fewer events (19 Sysmon vs. 35 defended, 4 security vs. 10 defended) but substantially more PowerShell events (104 vs. 34). This pattern suggests the defended run generated more detection telemetry (more alerts, more Defender-side logging) while the undefended run allowed the actual pypykatz execution to proceed quietly. The PowerShell volume increase in the undefended run is consistent with the ART module loading fully and running the complete test sequence without interruption.

## What This Dataset Does Not Contain

Sysmon EID 10 for the pypykatz process accessing LSASS directly is not in the 20-event sample — the preview shows only EID 10 events for the ART test framework child processes. The full dataset would contain the pypykatz-to-LSASS access event. There are no network events and no persistence artifacts. Registry access audit events (EID 4656/4663 for HKLM\SAM) are absent — pypykatz live mode reads from LSASS memory rather than the registry, so registry-based detection would not fire. The Python virtual environment (`venv_t1003_002`) was pre-staged; this dataset does not show the staging phase.

## Assessment

The pypykatz live lsa command line is directly visible in Sysmon EID 1, providing an unambiguous detection artifact. The binary path `C:\AtomicRedTeam\ExternalPayloads\venv_t1003_002\Scripts\pypykatz` with arguments `live lsa` is distinctive and should trigger on any reasonable process command line monitoring. The reduced event volume compared to the defended version is interesting — detection systems that rely on volume-based anomaly detection would not flag this. The dataset is valuable for testing string-based detection against pypykatz command lines and for understanding what a live LSA credential dump produces in Sysmon telemetry.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 / EID 4688 — pypykatz command line:** The string `pypykatz` appearing in a process image path or parent command line is a tier-1 detection. The `live lsa` subcommand arguments confirm the intent is live credential extraction.

2. **EID 1 — unusual binary in AtomicRedTeam ExternalPayloads path:** The path `C:\AtomicRedTeam\ExternalPayloads\` followed by any executable is a red team tooling indicator on production systems. More broadly, executables in paths outside standard system directories being invoked by `cmd.exe` as SYSTEM deserves scrutiny.

3. **Sysmon EID 10 — pypykatz accessing LSASS:** In the full dataset, the EID 10 event showing the pypykatz process opening `lsass.exe` with a memory read access mask (`0x1010` or `0x1FFFFF`) provides the definitive dump telemetry. The source image path containing `pypykatz` makes this unambiguous.

4. **EID 4688 — cmd.exe spawned by powershell.exe running as SYSTEM:** On a domain workstation, PowerShell running as SYSTEM spawning cmd.exe which then runs an executable from a temp or non-system path is an anomalous process tree that warrants investigation regardless of tool name.

5. **EID 4103 (PowerShell Module Logging):** Module logging events from the Invoke-AtomicRedTeam module combined with subsequent credential access tool execution chain the originating PowerShell session to the attack activity.

6. **Filesystem presence — pypykatz binary:** A file named `pypykatz` or located in a Python virtual environment's `Scripts\` directory on a production Windows system is itself an indicator of attack tool staging.
