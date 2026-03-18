# T1518.001-6: Security Software Discovery — Security Software Discovery - Sysmon Service

## Technique Context

T1518.001 (Security Software Discovery) covers adversary enumeration of defensive tooling installed on a target. Detecting the presence of Sysmon specifically is a common pre-exploitation step: if Sysmon is running, an attacker knows their process, network, and file operations will be logged and may adjust their tradecraft accordingly. One reliable method for detecting Sysmon — even without process listing — is to enumerate Windows kernel filter drivers using `fltMC.exe`. Sysmon registers as a minifilter driver under a well-known altitude number (385201), and its presence is visible to any user-mode process that can call `fltMC filters`. Detection focus typically centers on `fltMC.exe` execution with `findstr` or string filtering on the output, particularly when invoked from a scripting host.

## What This Dataset Contains

The core technique evidence is a process chain captured across all three channels. The command executed is:

```
cmd.exe /c fltmc.exe | findstr.exe 385201
```

Sysmon event ID 1 records four processes in sequence: `whoami.exe` (RuleName `T1033`), `cmd.exe` (RuleName `T1059.003`, CommandLine `"cmd.exe" /c fltmc.exe | findstr.exe 385201`), `fltMC.exe` (RuleName `T1518.001,technique_name=Security Software Discovery`, CommandLine `fltmc.exe`), and `findstr.exe` (RuleName `T1083`, CommandLine `findstr.exe 385201`). The Sysmon rule correctly identifies `fltMC.exe` with the T1518.001 tag.

Security event ID 4688 captures all four process creations with full command lines, confirming: parent of `cmd.exe` is `powershell.exe` (PID 0x76b4), parent of `fltMC.exe` and `findstr.exe` is `cmd.exe` (PID 0x34cc). All run as `NT AUTHORITY\SYSTEM`.

The PowerShell channel contains only ART test framework boilerplate: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in 4103, and `Set-StrictMode` fragments in 4104. No technique-specific script block is logged because the test invokes the command via a shell passthrough rather than a PowerShell cmdlet.

Sysmon event ID 10 records PowerShell opening `cmd.exe` with `GrantedAccess: 0x1FFFFF` (full access), tagged `T1055.001`. Event ID 11 records PowerShell writing `StartupProfileData-Interactive` at startup.

## What This Dataset Does Not Contain

The PowerShell channel carries no technique-relevant script blocks — the actual discovery command was passed as a shell command string, not executed within a PowerShell script block. A detection rule relying solely on PowerShell 4104/4103 for this variant would produce no alert.

There is no output of `fltMC.exe` captured anywhere. The dataset shows the enumeration attempt but cannot confirm whether Sysmon's filter altitude 385201 was found in the output. No Defender block event fires; `fltMC` and `findstr` are standard system utilities.

The Sysmon include-mode configuration did not capture the `powershell.exe` launcher process itself in event ID 1 — only child processes that matched include rules (`cmd.exe` via T1059.003 rule, `fltMC.exe` via T1518.001 rule, `findstr.exe` via T1083 rule). The full parent powershell.exe process create is absent from Sysmon.

## Assessment

This dataset is strong for process-lineage–based detection. The combination of Security 4688 and Sysmon event ID 1 provides the most direct evidence: `fltMC.exe` executed with no arguments, as a child of `cmd.exe` containing `findstr 385201` in the parent command line. The T1518.001 tag on the `fltMC.exe` event ID 1 record is immediately actionable. The process chain `powershell.exe → cmd.exe → fltMC.exe` is highly anomalous on a workstation. To strengthen the dataset, capturing the stdout output of `fltMC.exe` (e.g., via a file write or ETW trace) would allow building detection logic that confirms a successful enumeration rather than just the attempt.

## Detection Opportunities Present in This Data

1. **Sysmon event ID 1 for fltMC.exe tagged T1518.001** — The sysmon-modular configuration applies the T1518.001 rule name directly to `fltMC.exe` process creates, making this a direct filter.
2. **Security 4688 for cmd.exe with fltmc in command line** — `"cmd.exe" /c fltmc.exe | findstr.exe 385201` is a precise, low-noise detection string; the altitude number 385201 is Sysmon-specific.
3. **Process chain: powershell.exe → cmd.exe → fltMC.exe** — This parent-child-grandchild chain visible via 4688 creator/new process fields is unusual on a managed workstation.
4. **fltMC.exe spawned from a scripting interpreter** — Any `fltMC.exe` with a parent of `cmd.exe`, `powershell.exe`, `wscript.exe`, or `cscript.exe` is a high-confidence detection opportunity.
5. **findstr.exe as sibling of fltMC.exe in the same cmd session** — The combination of `fltMC.exe` and `findstr.exe` as siblings in a pipe command indicates output filtering consistent with targeted security product enumeration.
