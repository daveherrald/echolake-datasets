# T1218.001-7: Compiled HTML File — Invoke CHM Shortcut Command with ITS and Help Topic

## Technique Context

T1218.001 (Compiled HTML File) is a defense evasion technique where attackers abuse the Microsoft HTML Help executable (`hh.exe`) to proxy execution of malicious code. HTML Help files (.chm) can embed ActiveX controls, JavaScript, or VBScript that execute when the file is opened. The ITS (InfoTech Storage) protocol handler — accessible via `ms-its:` URIs — allows an attacker to reference content inside a CHM file, including shortcut commands that trigger code execution.

This test uses the `Invoke-ATHCompiledHelp` function from the AtomicTestHarnesses project, which exercises `hh.exe` via the ITS protocol handler with a shortcut command targeting an HTML topic (`-InfoTechStorageHandler its -TopicExtension html -ExecuteShortcutCommand`). In theory, this should produce a `hh.exe` process creation event with a `ms-its:` command-line argument and potentially spawn a child process. It is a stealthier variant compared to directly opening a CHM file because the ITS handler is invoked programmatically.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17T16:49:18Z to 16:49:21Z) across 149 total events: 108 PowerShell, 4 Security, and 37 Sysmon.

**Process execution chain (Security EID 4688 and Sysmon EID 1):** The test framework spawned a child PowerShell process (PID 0x4748 / 18248) from the parent test framework process (PID 0x35c0). The command line recorded by both Security EID 4688 and Sysmon EID 1 is:

```
"powershell.exe" & {Invoke-ATHCompiledHelp -ExecuteShortcutCommand -InfoTechStorageHandler its -TopicExtension html -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}
```

The Sysmon ProcessCreate event carries RuleName `technique_id=T1083,technique_name=File and Directory Discovery`, indicating that the sysmon-modular config matched the PowerShell command line under its file discovery rule — not a dedicated CHM rule. The process ran as `NT AUTHORITY\SYSTEM` under `C:\Windows\TEMP\` as the working directory.

**Validation whoami execution:** Security EID 4688 and Sysmon EID 1 both record `"C:\Windows\system32\whoami.exe"` (PID 0x47e0 / 18400) spawned by the same parent PowerShell. This is the test framework confirming execution context.

**Process access events (Sysmon EID 10):** PowerShell (PID 13760) opened both whoami.exe (PID 18400) and the child PowerShell process (PID 18248) with full access rights (0x1FFFFF). The rule name on these events is `technique_id=T1055.001,technique_name=Dynamic-link Library Injection` — a sysmon-modular heuristic for cross-process open with high access rights.

**Image loads (Sysmon EID 7):** The test framework PowerShell session loaded `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, `clrjit.dll`, `MpOAV.dll`, `MpClient.dll`, and `urlmon.dll`. The `urlmon.dll` load (OLE32 Extensions for Win32) is notable — it is associated with URL/protocol handler resolution and is typically loaded when a process is about to resolve a URI such as `ms-its:`.

**Named pipe creation (Sysmon EID 17):** Two PowerShell host pipes were created — `\PSHost.134182397574848600.13760.DefaultAppDomain.powershell` and `\PSHost.134182397627649185.17504.DefaultAppDomain.powershell` — confirming two separate PowerShell host sessions were active.

**File creation (Sysmon EID 11):** One file creation was captured: the PowerShell startup profile data file at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`. This is routine PowerShell infrastructure activity.

**PowerShell script block logging (EID 4104):** The 108 PowerShell events contain the test framework setup blocks (`Set-ExecutionPolicy Bypass -Scope Process -Force`, `$ErrorActionPreference = 'Continue'`) and the cleanup invocation (`Invoke-AtomicTest T1218.001 -TestNumbers 7 -Cleanup`). The key technique block is captured in Sysmon EID 1 rather than PS EID 4104 — the `Invoke-ATHCompiledHelp` call was passed directly as a command-line argument to the child PowerShell process.

## What This Dataset Does Not Contain

The dataset lacks the single most important artifact for T1218.001 detection: **there are no `hh.exe` process creation events** in any channel. Neither Security EID 4688 nor Sysmon EID 1 records `hh.exe` launching. The sysmon-modular configuration explicitly includes `hh.exe` in its LOLBin process creation include rules, so if `hh.exe` had executed, it would have appeared.

The most likely explanation is that `Invoke-ATHCompiledHelp` could not locate or create the required `Test.chm` file in the working directory at test execution time, causing the function to abort before invoking `hh.exe`. This is consistent with the cleanup script removing CHM test artifacts — if the file was missing at invocation, the shortcut command execution path would not be reached.

Also absent:
- Network connections from `hh.exe` (Sysmon EID 3)
- DNS queries (Sysmon EID 22)
- Registry modifications related to CHM execution
- Any child process spawned by `hh.exe` itself

## Assessment

This dataset does not capture a successful `hh.exe` execution. What you get is the test framework invocation telemetry — including the full `Invoke-ATHCompiledHelp` command line in both a Sysmon EID 1 process create and Security EID 4688 — without the downstream `hh.exe` activity that would constitute the core technique evidence. The `urlmon.dll` image load into the test framework PowerShell suggests the process attempted URI resolution, but did not progress to `hh.exe` process creation.

Comparing this with the defended variant: the defended dataset (36 Sysmon, 10 Security, 45 PowerShell events) similarly contains no `hh.exe` process creates. This test appears to have been consistently non-executable in this environment regardless of Defender state, likely due to a missing or inaccessible test artifact rather than an endpoint protection block. The undefended run does produce more PowerShell instrumentation (108 vs. 45 events) due to the absence of AMSI filtering, providing better visibility into the test framework initialization.

## Detection Opportunities Present in This Data

**PowerShell command line containing `Invoke-ATHCompiledHelp` and ITS handler arguments (Sysmon EID 1, Security EID 4688):** The child PowerShell process created to run the technique carries the explicit function name and arguments in its command line. Real attacker tooling would encode or obfuscate this, but the pattern of PowerShell launching with CHM/ITS-related arguments is meaningful.

**`urlmon.dll` loaded into a PowerShell process (Sysmon EID 7):** The OLE32 URL handler DLL is not a normal component of PowerShell execution. Its presence as an image load — especially tagged with the Internet Explorer product string — indicates the host process attempted to resolve a URL-type resource (in this case, an `ms-its:` URI path).

**Cross-process OpenProcess with 0x1FFFFF (PROCESS_ALL_ACCESS) from PowerShell (Sysmon EID 10):** While common in test framework contexts, PowerShell opening child processes with full access rights triggers the sysmon-modular T1055.001 rule. In production environments, this access pattern from PowerShell to a newly-spawned process warrants review.

**Process ancestry:** The process tree shows PowerShell spawning both whoami.exe and a second PowerShell process from within `C:\Windows\TEMP\` as SYSTEM. The working directory (`C:\Windows\TEMP\`) combined with SYSTEM context and LOLBIN execution is an independently useful hunting signal.

If `hh.exe` were to execute successfully in a comparable environment, the primary detection opportunity would be `hh.exe` process creation carrying a command line with `ms-its:` or a `.chm` file path, particularly when `hh.exe` is spawned by PowerShell or another scripting host rather than an interactive user session.
