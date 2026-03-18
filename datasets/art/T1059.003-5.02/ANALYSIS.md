# T1059.003-5: Windows Command Shell — Command Prompt Read Contents from CMD File and Execute

## Technique Context

T1059.003 (Windows Command Shell) covers cmd.exe execution. This test demonstrates input redirection in cmd.exe: feeding a batch file's contents to cmd using `cmd < file.cmd` (via the `/r` redirect-and-run flag) rather than calling the batch file directly. Input redirection means the commands are read from stdin rather than being specified on the command line, which means the command line visible in process creation events does not reveal what will actually execute.

The technique has operational value because basic command-line monitoring that looks for suspicious patterns in `ProcessCommandLine` fields would see only `cmd /r cmd<file.cmd` — not the payload commands contained in the file. The batch file's content is effectively a hidden payload from the perspective of command-line-only detection.

In this test, the batch file at `C:\AtomicRedTeam\atomics\T1059.003\src\t1059.003_cmd.cmd` contains a command that ultimately launches `calc.exe` — a benign proxy for arbitrary payload execution. The execution chain produced is:

```
cmd.exe /c cmd /r cmd<"C:\AtomicRedTeam\atomics\T1059.003\src\t1059.003_cmd.cmd"
  → cmd  /r cmd
    → cmd
      → cmd.exe /c c:\windows\system32\calc.exe
        → calc.exe
```

This deep nesting (four cmd.exe processes before the final payload) is an artifact of the `/r` redirect chain and illustrates how input redirection creates non-obvious process trees.

Windows Defender does not block this technique in either the defended or undefended context — it uses only legitimate Windows utilities executing from normal paths.

## What This Dataset Contains

Security EID 4688 records all 8 process creations in the chain. The complete sequence:

1. PowerShell spawns outer cmd: `"cmd.exe" /c cmd /r cmd<"C:\AtomicRedTeam\atomics\T1059.003\src\t1059.003_cmd.cmd"`
2. `cmd  /r cmd` — the /r redirect-and-run instruction, reading from the batch file via stdin
3. `cmd` — bare cmd.exe invoked from within the redirection
4. `cmd.exe  /c c:\windows\system32\calc.exe` — the batch file's actual payload command
5. `c:\windows\system32\calc.exe` — the final executed binary
6. Two `whoami.exe` from PowerShell (pre/post test context checks)
7. Cleanup cmd: `"cmd.exe" /c` (empty, no-op)

Sysmon EID 1 captures 7 of these processes. The cmd.exe events are all tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. Process details include SHA1 and MD5 hashes for the cmd.exe instances: `SHA1=13E9BB7E85FF9B08C26A440412E5CD5D296C4D35,MD5=5A6BE4D251951...` — confirming the authentic Windows cmd.exe binary rather than a replacement. calc.exe is also tagged with Sysmon EID 1 (visible in Security 4688 event chain).

Sysmon EID 10 records four full-access handle opens (0x1FFFFF) from PowerShell to various processes in the chain — the ART test framework monitoring its spawned processes.

Sysmon EID 11 records the PowerShell startup profile write (not related to the test payload). No EID 11 for the batch file read.

The PowerShell channel has 104 events (102 EID 4104, 2 EID 4103). EID 4103 captures `Write-Host "DONE"` — test completion. The 102 EID 4104 blocks contain the test framework and the ART test invocation.

Compared to the defended version (23 sysmon, 18 security, 34 powershell), the undefended version has 17 sysmon, 8 security, and 104 powershell events. The defended version had more security events (18 vs 8) — the defended execution also ran successfully (no blocking), so the difference may reflect timing or collection window variation rather than substantive execution differences.

## What This Dataset Does Not Contain

The contents of `t1059.003_cmd.cmd` are not recorded in any event channel. The only evidence of what the batch file contained is the `cmd.exe /c c:\windows\system32\calc.exe` command line visible in process creation events — that is, the last step of the chain is visible, but not the intermediate batch commands that led there. File read events (Sysmon does not capture file-read access, only file creation) for the batch file are absent.

No registry events. No network events. The `calc.exe` execution is a proxy payload; the actual commands an attacker would stage in the batch file are not represented in this test's execution.

## Assessment

This is a well-formed dataset for the input-redirection command-chain pattern. The full process tree from PowerShell through four nested cmd.exe instances to calc.exe is captured across both Security EID 4688 and Sysmon EID 1, providing redundant and complementary process-creation telemetry. The double-space in `cmd  /r cmd` (an artifact of how the shell expands the redirect) and the bare `cmd` process are distinctive process tree markers.

The key detection challenge this dataset illustrates is that the batch file's contents are not visible in any process creation event until the final `cmd.exe /c c:\windows\system32\calc.exe` step — meaning a sufficiently clever attacker could stage a multi-step payload in a batch file where only the last step (the actual execution) appears in command-line monitoring.

## Detection Opportunities Present in This Data

1. EID 4688 / Sysmon EID 1 `CommandLine` containing `cmd /r cmd<` — the input-redirection-to-run pattern where cmd reads from a file via stdin.
2. Process chain depth: four nested `cmd.exe` instances before the final payload — an unusually deep cmd.exe nesting tree is a behavioral anomaly.
3. EID 4688 with `cmd  /r cmd` (double-space) as a child of `cmd.exe /c cmd /r cmd<"..."` — the expansion artifact of the input-redirect chain producing extra whitespace.
4. EID 4688 for bare `cmd` (no arguments) as a child of `cmd  /r cmd` — a no-argument cmd.exe in a chain where the parent is running a redirect operation.
5. Sysmon EID 1 for `cmd.exe` repeatedly tagged `technique_id=T1059.003` through a parent-child chain — multiple Sysmon rule fires along a single execution path.
6. EID 4688 showing `calc.exe` or another unusual binary launched as the final payload in a cmd.exe chain originating from PowerShell — the payload at the end of a deep process tree.
7. EID 4688 path `C:\AtomicRedTeam\atomics\T1059.003\src\t1059.003_cmd.cmd` — the batch file staging path; in real attacks, equivalent files would appear in writable user-controlled locations like `%TEMP%` or `%APPDATA%`.
