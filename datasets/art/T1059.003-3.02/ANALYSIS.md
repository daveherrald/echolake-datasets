# T1059.003-3: Windows Command Shell — Suspicious Execution via Environment Variable Obfuscation

## Technique Context

T1059.003 (Windows Command Shell) covers adversary use of `cmd.exe` to execute commands and scripts. This test demonstrates command-line obfuscation using Windows environment variable substring expansion. The technique constructs the string `cmd` dynamically by extracting a single character from an environment variable: `%LOCALAPPDATA:~-3,1%` extracts the third-to-last character of the `LOCALAPPDATA` path, which on a standard Windows system ends in `...AppData\Local`, yielding the character `c`. Combined with literal `md`, this produces `cmd` — but the actual command line reads as `%LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD!`.

This class of obfuscation is used to evade static detection rules that look for literal `cmd.exe` or `cmd /c` in ProcessCommandLine fields. Rules relying on exact substring matching would miss `%LOCALAPPDATA:~-3,1%md`. Detection requires either dynamic expansion of environment variables before matching, behavioral analysis of the process tree (a cmd.exe child spawning another cmd.exe), or file-creation monitoring.

This technique is notably benign in its payload — `echo Hello, from CMD! > hello.txt` — but the obfuscation machinery is exactly what would appear in real attacker tooling. The file written, `C:\Windows\Temp\hello.txt`, confirms execution succeeded.

In the defended version, Windows Defender did not block this execution — the technique uses only legitimate system utilities and writes a harmless text file. The undefended dataset is therefore equivalent to the defended one in terms of what executed, differing only in overall collection context.

## What This Dataset Contains

Security EID 4688 records five process creations. The key ones:

1. `"cmd.exe" /c %LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt` — the obfuscated outer cmd.exe (note: EID 4688 shows the raw command line before variable expansion).
2. `cmd  /c echo Hello, from CMD!` — the inner cmd.exe after the outer expands the obfuscation, with a double-space between `cmd` and `/c` as an expansion artifact.

Sysmon EID 1 captures the same two processes with additional detail. The outer cmd.exe (PID 648, parent PowerShell PID 7152) is tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. Its command line in Sysmon shows `%%LOCALAPPDATA:~-3,1%%md` (Sysmon double-escapes percent signs). The inner cmd.exe (PID 4964) has `cmd  /c echo Hello, from CMD!` with the double-space.

Sysmon EID 11 records the file creation: `TargetFilename: C:\Windows\Temp\hello.txt` written by `cmd.exe` (PID 648). The rule match is `technique_id=T1574.010,technique_name=Services File Permissions Weakness` — the Sysmon rule fires because `C:\Windows\Temp\` is a monitored write location.

Sysmon EID 10 shows PowerShell (PID 7152) accessing the outer cmd.exe (PID 5240, `GrantedAccess: 0x1FFFFF`) and a second process (PID 648, same full access) — the test framework monitoring its child processes.

The PowerShell channel has 105 events (103 EID 4104, 2 EID 4103). EID 4103 captures a `Write-Host "DONE"` invocation — the ART test signaling completion. The 103 EID 4104 blocks include the test framework overhead and the test invocation.

The Application log (EID 15) records Defender status update — background housekeeping, not related to this test.

Compared to the defended version (18 sysmon, 12 security, 34 powershell), the undefended version has more events across all channels (20 sysmon, 5 security, 105 powershell). The extra events reflect the absence of any blocking — the full execution chain runs to completion.

## What This Dataset Does Not Contain

No registry modification events. No network activity. The `type hello.txt` command in the outer cmd line would have output the file content to stdout, but that output is not captured in any event channel — stdout from cmd.exe is not logged by default.

The PowerShell script block logging does not include the specific PowerShell command that invoked the ART test (`Invoke-AtomicTest T1059.003 -TestNumbers 3`) — the actual test invocation script block is present in the 103 EID 4104 events but not in the 20 samples. The `Write-Host "DONE"` EID 4103 confirms the test completed.

## Assessment

This is a clean, fully-executed dataset for environment variable obfuscation in cmd.exe. Both the obfuscated command line (in EID 4688 and Sysmon EID 1) and the de-obfuscated child process command line are captured, providing both the attacker-visible artifact and the post-expansion result. The EID 11 file creation confirms payload delivery. This is a useful training set for detection models that need to learn the environment variable substring syntax as an obfuscation indicator.

The technique ran successfully in both the defended and undefended environments because it uses no offensive payloads — the obfuscation is the detection target, not any malware behavior.

## Detection Opportunities Present in This Data

1. EID 4688 `CommandLine` containing `%LOCALAPPDATA:~` or similar environment variable substring syntax — the presence of `:~` or `:~-` in a cmd.exe command line is a strong obfuscation indicator.
2. Sysmon EID 1 for `cmd.exe` with `CommandLine` containing `%%` (double-percent escape as shown in Sysmon output) combined with a substring operator — Sysmon's representation of the same pattern.
3. EID 4688 with `cmd.exe` spawning a child `cmd.exe` where the child's command line begins with `cmd  /c` (double-space) — an artifact of environment variable expansion producing extra whitespace.
4. Sysmon EID 11 `TargetFilename: C:\Windows\Temp\hello.txt` written by `cmd.exe` — a cmd.exe process creating files in `%TEMP%` as a payload delivery indicator.
5. Sysmon EID 1 tagged `technique_id=T1059.003` on a `cmd.exe` process with obfuscated command line — the Sysmon detection rule firing on the expansion syntax.
6. EID 4688 `& type hello.txt` appended to the command chain — output of the newly created file immediately after creation, consistent with attacker verification of successful file write.
7. PowerShell EID 4103 capturing `Write-Host "DONE"` — test completion signal; in non-test contexts, similar completion signals may appear in legitimate or malicious automation scripts.
