# T1559-4: Inter-Process Communication — 4.2 and Later

## Technique Context

T1559 covers Inter-Process Communication as an execution channel. Test 4 emulates the named pipe pattern introduced in Cobalt Strike 4.2 for post-exploitation modules. Prior to version 4.2, CS used predictable or hardcoded pipe names. Version 4.2 introduced randomized post-exploitation pipe names to evade signature-based detections. In a live deployment, the beacon creates a short-lived pipe with a randomized name and passes shellcode to a fork-and-run post-exploitation job through it. This is the mechanism behind CS's `execute-assembly`, `powerpick`, and similar post-ex features.

## What This Dataset Contains

The dataset spans 5 seconds (01:15:40–01:15:45 UTC) across 26 Sysmon events, 10 Security events, and 34 PowerShell events — the same counts as test 1, indicating highly consistent test framework execution.

The core execution captured is:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 4
```

Security 4688 records this command line with the full parent chain (SYSTEM `powershell.exe` → `cmd.exe`). The `whoami.exe` ART preflight is captured in both Security 4688 and Sysmon EID 1. Sysmon EID 10 records the SYSTEM PowerShell process accessing both `whoami.exe` and `cmd.exe` child processes with access rights tagged as `technique_id=T1055.001`. `cmd.exe` exits with status `0x1`, matching the blocked-execution pattern seen in tests 1–3.

Two `\PSHost.*` named pipes appear in Sysmon EID 17, both from SYSTEM PowerShell processes. The PowerShell 4103 log records `Set-ExecutionPolicy Bypass -Scope Process -Force` under `ACME\SYSTEM`.

## What This Dataset Does Not Contain (and Why)

No post-4.2 CS pipe name (typically short random strings like `\XXXXXXXX` or similar) appears in Sysmon EID 17. The randomization that makes CS 4.2+ pipes harder to detect by name is irrelevant here because the pipe was never created — the executor was blocked before it could attempt the connection. Sysmon EID 18 (PipeConnected) is absent.

No post-exploitation job artifacts are present. In a real CS deployment, a fork-and-run job would execute (e.g., running Mimikatz, executing a .NET assembly) through the pipe. None of that activity occurs here. No child processes of the post-ex job, no credential access events, no file artifacts from post-ex modules.

Windows Defender terminated the attempt. The 0x1 exit code and absence of any named pipe creation by the executor are the observable indicators of the block.

## Assessment

This dataset is structurally identical to tests 1, 2, and 3 at the observable telemetry level. The only distinguishing characteristic is `--pipe 4` in the command line, which maps to the CS 4.2+ post-ex pipe variant. The four pipe tests (T1559-1 through T1559-4) collectively document a complete set of Cobalt Strike named pipe emulation attempts under Defender, all blocked at the same execution stage. The dataset is most valuable when analyzed alongside its siblings to confirm that detection logic for CS pipe IPC does not require pipe-name-specific signatures and can operate on the process chain and command-line patterns alone.

## Detection Opportunities Present in This Data

- **Security 4688**: `namedpipes_executor.exe --pipe 4` under SYSTEM from `powershell.exe`; the `--pipe 4` argument distinguishes this test as the CS 4.2+ post-ex variant.
- **Sysmon EID 1**: `whoami.exe` and `cmd.exe` spawned by SYSTEM `powershell.exe`; combining parent image, user context, and command line provides a reliable detection pivot.
- **Sysmon EID 10**: `powershell.exe` accessing child processes with DLL-injection-class access; rule `technique_id=T1055.001` fires on both the `whoami.exe` and `cmd.exe` accesses.
- **Security 4689**: `cmd.exe` exit status `0x1` within under 100ms of creation; this rapid-exit pattern across all four pipe tests is a reliable blocked-attempt indicator.
- **Sysmon EID 17**: `\PSHost.*` pipes only; detecting the *absence* of non-PSHost pipes when a named pipe IPC test runs is a useful negative indicator in a labeled training dataset.
- **Cross-dataset correlation**: The four T1559-1 through T1559-4 datasets share identical process chain patterns; a detection tuned on one should fire on all four, making them a useful regression suite.
