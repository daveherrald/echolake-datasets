# T1003.001-7: LSASS Memory — LSASS read with pypykatz

## Technique Context

pypykatz is a Python implementation of Mimikatz's credential extraction functionality. Unlike the native Mimikatz binary, pypykatz runs as a Python script and was originally designed to run on non-Windows platforms — parsing LSASS dumps and SAM hives on an attacker's Linux or macOS machine. The ART variant tested here uses a Windows-compatible `pypykatz` executable (a PyInstaller-packaged Python binary) and invokes it with the `live lsa` subcommand, which reads directly from the running LSASS process rather than from a dump file.

The `pypykatz live lsa` command is the real-time equivalent of `mimikatz sekurlsa::logonpasswords full`. It opens a process handle to LSASS, reads the credential structures from memory, and prints the results. This means it generates Sysmon EID 10 (Process Access) events targeting `lsass.exe` — the primary detection indicator. The Python packaging means the binary is large and doesn't look like a typical compiled credential dumper; it's actually a Python runtime with the pypykatz module bundled. This packaging can confuse some hash-based detection approaches.

In the defended version, Defender blocked pypykatz execution with exit status 0x1 before LSASS access occurred. The undefended run should show the live LSASS memory read.

## What This Dataset Contains

This dataset produces 12 Sysmon events (4 EID 1, 4 EID 10, 3 EID 11, 1 EID 7), 104 PowerShell events (102 EID 4104, 2 EID 4103), and 4 Security EID 4688 events — one of the smallest collections in the T1003.001 series, making the 20-event sample very representative of the full dataset.

The **Sysmon channel** samples are fully visible:

**EID 1 (Process Create)**: `whoami.exe` (PID 3976) and `cmd.exe` (PID 3232) with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\...` (the pypykatz launcher), and `whoami.exe` (PID 2444), and `cmd.exe` (PID 2740) with command line `"cmd.exe" /c del "%%temp%%\nanodump.dmp" > nul 2> nul` — a cleanup command that references `nanodump.dmp` (leftover from T1003.001-4's cleanup having already run, or the test framework's catch-all cleanup pattern).

**EID 10 (Process Access)**: `powershell.exe` (PID 4940) accessing `whoami.exe` (PID 3976) with `GrantedAccess: 0x1FFFFF` and `powershell.exe` (PID 4940) accessing `whoami.exe` (PID 2444) with `GrantedAccess: 0x1FFFFF`. Both with call trace `C:\Windows\SYSTEM32\ntdll.dll`. The 4 EID 10 events include these test framework-level accesses; whether the pypykatz LSASS access appears depends on whether `venv_t1003_001\Scripts\pypykatz` triggered the sysmon-modular ProcessAccess filter.

**EID 7 (Image Load)**: 1 image load event — a DLL loaded by the pypykatz execution chain.

**EID 11 (File Create)**: 3 file creation events from the test window.

The **Security channel** (4 EID 4688) records: `whoami.exe` (PID 0xf88), `cmd.exe` (PID 0xca0) — the pypykatz launcher — `whoami.exe` (PID 0x98c), and `cmd.exe` (PID 0xab4) for cleanup. The defended analysis identified the full command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1003_001\Scripts\pypykatz" live lsa` in the EID 4688 event — this command line is present in the undefended dataset.

The **PowerShell channel** (102 EID 4104, 2 EID 4103) contains test framework setup/cleanup blocks and the EID 4103 output. The defended analysis noted that the defended version's EID 4103 showed Defender's `MpOAV.dll` and `MpClient.dll` loading during the blocking operation. In the undefended version, these Defender DLL loads will be absent, and instead the pypykatz Python runtime DLL loads may appear in EID 7.

The small Sysmon total (12 events) contrasts sharply with tests that coincide with Windows Update activity (thousands of EID 11). The clean event count makes this a straightforward dataset to work with.

## What This Dataset Does Not Contain

The pypykatz executable runs from `venv_t1003_001\Scripts\pypykatz` within the `ExternalPayloads` staging directory. Like other external payload binaries, it likely doesn't appear directly in Sysmon EID 1 due to include-mode filtering. Its process creation is captured in Security EID 4688 via the `cmd.exe` wrapper.

The dataset has only 1 Sysmon EID 7 (Image Load) event. The pypykatz Python runtime loads many DLLs at startup, but the sysmon-modular configuration's include-mode filtering for image loads would only capture DLLs matching known-suspicious patterns.

No Sysmon EID 3 (Network Connection) events appear. pypykatz's `live lsa` command reads from local LSASS memory and does not make network connections.

## Assessment

Despite its small event count, this dataset provides useful detection telemetry for pypykatz's `live lsa` execution. The Security EID 4688 command line — the path `venv_t1003_001\Scripts\pypykatz` combined with `live lsa` — is a specific and actionable indicator. The fact that the test shows a cleanup command referencing `nanodump.dmp` is a minor artifact from sequential test execution in the same session. For detection engineering, the most immediately actionable signal is the command-line pattern in Security EID 4688, with the pypykatz LSASS access event (EID 10) as the deeper indicator if the sysmon-modular filter captured it.

## Detection Opportunities Present in This Data

1. Security EID 4688 with `ProcessCommandLine` containing `pypykatz` and `live lsa` — a direct command-line match on the tool and subcommand. The path `venv_t1003_001\Scripts\pypykatz` identifies the specific ART staging location.

2. Sysmon EID 10 with `TargetImage` containing `lsass.exe` and `SourceImage` matching the pypykatz binary path — the primary live LSASS access indicator for this tool.

3. Security EID 4688 with a `cmd.exe` spawning an executable from a Python virtual environment staging path (`Scripts\pypykatz`) — the `venv` directory structure in the path is unusual for a system utility and detectable by path pattern matching.

4. Sysmon EID 1 showing `cmd.exe` with command line containing a path under `ExternalPayloads\venv_` — the virtual environment staging path is a distinctive artifact of how this specific ART test deploys pypykatz.

5. Any process creation where the image path contains `pypykatz` — regardless of the invocation context, a process with this name in a Windows environment is effectively always malicious.

6. Correlation of the cleanup `del "%%temp%%\nanodump.dmp"` command with the pypykatz execution — while this is a cross-test artifact in the dataset, in real deployments it represents an attacker performing sequential LSASS operations and cleaning up between attempts.
