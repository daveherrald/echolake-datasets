# T1218.005-2: Mshta — Mshta Executes VBScript to Execute Malicious Command

## Technique Context

T1218.005 (Mshta) involves abusing `mshta.exe`, the Microsoft HTML Application Host, to execute inline script content. This test demonstrates one of the most common mshta abuse patterns: passing VBScript directly as a `vbscript:` URI argument that uses `Wscript.Shell.Run` to spawn a secondary process. The pattern allows an attacker to use mshta.exe as a one-step launcher that bridges from a command-line invocation to an arbitrary child process, with the scripting engine handling the actual process creation.

The full payload pattern is: `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""<command>"":close")`. This executes entirely within the mshta.exe process — no HTA file is written to disk, the VBScript runs inline, and the only observable artifact is the child process spawned by `Wscript.Shell.Run`.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17T16:50:47Z to 16:50:50Z) across 175 total events: 97 PowerShell, 31 Security, 45 Sysmon, 1 Application, 1 System, 1 WMI.

**Complete three-step execution chain (Security EID 4688):** All three process creation events in the chain are captured:

1. `cmd.exe` (PID 0x446c) spawned by PowerShell (PID 0x4570) with:
   ```
   "cmd.exe" /c mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"":close")
   ```

2. `mshta.exe` (PID 0x47b0) spawned by `cmd.exe` (PID 0x446c) with:
   ```
   mshta  vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1"":close")
   ```

3. `powershell.exe` (PID 0x3f64) spawned by `mshta.exe` (PID 0x47b0) with:
   ```
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noexit -file C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1
   ```

This is the complete, unobstructed mshta-to-PowerShell execution chain. The Security EID 4688 events capture each hop with full command lines and parent-child PID relationships.

**Sysmon EID 1 — cmd.exe with the VBScript payload:** The sysmon-modular config captures the cmd.exe with `technique_id=T1059.003` rule match, confirming the command shell LOLBin rule fired.

**Security EID 4799 — Group membership enumeration (21 events):** The `powershell.ps1` script spawned by mshta.exe executed group enumeration. EID 4799 (security-enabled local group membership enumerated) fired 21 times, covering groups including `Administrators` (S-1-5-32-544), `Backup Operators` (S-1-5-32-551), and others. This is the payload execution artifact — the script that mshta launched is actively enumerating local groups.

**WMI EID 5860 — Temporary subscription:** The WMI event log records a temporary subscription query: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'`. This is a WMI watch for WinRM process activity, possibly from the test framework monitoring for test completion.

**System EID 7040 — BITS service start type change:** The Background Intelligent Transfer Service (BITS) had its start type changed from demand start to auto start. This likely occurred within the `powershell.ps1` payload or as a side effect of the mshta execution context activating network services.

**Security EID 4624/4672:** Service logon and special privileges events reflecting service account activity triggered by the service configuration change.

## What This Dataset Does Not Contain

The content of `C:\AtomicRedTeam\atomics\T1218.005\src\powershell.ps1` is not captured — there are no PowerShell EID 4104 events logging the script's content in a way that reveals its full logic. The 21 EID 4799 group enumeration events indicate what it did (enumerate local groups) but not the full script. There are also no network connection events from `mshta.exe`, as this test uses a local file path rather than a remote URL.

## Assessment

This is the most evidence-rich mshta test in this series. You get the complete three-hop execution chain (PowerShell → cmd.exe → mshta.exe → powershell.exe) with full command lines at every step, plus direct evidence of payload execution in the form of 21 EID 4799 group enumeration events. The dataset demonstrates that `mshta.exe` successfully ran its VBScript payload and that payload performed substantive post-execution activity.

In the defended variant (56 Sysmon, 15 Security, 44 PowerShell events), Defender blocks `mshta.exe` execution — the cmd.exe spawn is recorded but `mshta.exe` never starts, and there are zero EID 4799 events. The undefended dataset's 31 Security events (vs. 15 defended) reflects the richer trail from the full execution chain plus the group enumeration events. The absence of AMSI also allows more PowerShell script block content to flow, contributing to the 97 vs. 44 PowerShell event count difference.

## Detection Opportunities Present in This Data

**`mshta.exe` with a `vbscript:` argument (Security EID 4688, Sysmon EID 1):** The `mshta.exe` command line contains the entire attack payload. The `vbscript:Execute(...)` URI scheme used as a command-line argument is a signature pattern for inline VBScript execution through mshta — this approach avoids writing any HTA file to disk.

**`mshta.exe` spawning PowerShell (Security EID 4688):** The parent-child relationship mshta.exe (PID 0x47b0) → powershell.exe (PID 0x3f64) is the result of the VBScript `Wscript.Shell.Run` call. `mshta.exe` spawning PowerShell, cmd.exe, or other command interpreters is the primary behavioral IOC for this class of technique.

**`cmd.exe` command line containing `mshta vbscript:Execute` (Security EID 4688):** The attack pattern of using `cmd.exe /c` to invoke mshta with an inline `vbscript:Execute` block is a commonly-documented, high-confidence detection pattern. The `CreateObject(""Wscript.Shell"").Run` double-quoted pattern within the VBScript is a specific indicator of the Wscript.Shell process launch method.

**EID 4799 group enumeration from an mshta-spawned process:** Twenty-one group membership enumeration events from a process chain rooted at mshta.exe indicates reconnaissance activity executing through the mshta execution path. Correlating 4799 bursts back through the process ancestry to a mshta.exe parent links the enumeration to the LOLBin execution.

**WMI temporary subscription for process tracking (WMI EID 5860):** A WMI subscription watching for `wsmprovhost.exe` starts, originating from a SYSTEM process (`ClientProcessID = 18392`) during the test execution window, indicates the payload or test framework used WMI for process monitoring.
