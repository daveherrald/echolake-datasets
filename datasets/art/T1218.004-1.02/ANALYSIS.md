# T1218.004-1: InstallUtil — CheckIfInstallable Method Call

## Technique Context

T1218.004 (InstallUtil) is a defense evasion technique that abuses `InstallUtil.exe`, a signed .NET Framework utility used to install and uninstall server resources. The binary can execute arbitrary code contained in .NET assemblies that implement the `System.Configuration.Install.Installer` class. Attackers craft malicious assemblies with code in constructors or installer methods, then invoke `InstallUtil.exe` against them.

The `CheckIfInstallable` method variant exercises whether the assembly passes validation checks before installation proceeds. The Invoke-ATHCompiledHelp/InstallUtil test framework (`Invoke-BuildAndInvokeInstallUtilAssembly`) from the AtomicTestHarnesses project dynamically compiles a minimal .NET assembly, writes it to disk as a `.dll`, and invokes `InstallUtil.exe` against it. This test uses `-MinimumViableAssembly`, meaning the assembly contains only a constructor — the absolute minimum for code execution through this path.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17T16:49:38Z to 16:49:42Z) across 175 total events: 115 PowerShell, 7 Security, 53 Sysmon, 3 Application, and 1 Task Scheduler event.

**Full execution chain (Security EID 4688):** The test framework spawned a child PowerShell process (PID 0x4594) from the parent test framework (PID 0x3f50). The Security EID 4688 for that child shows it received the `Invoke-BuildAndInvokeInstallUtilAssembly` function. That child PowerShell (0x4594) then spawned `csc.exe` (PID 0x4428, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) to compile the test assembly. The C# compiler in turn spawned `cvtres.exe` (PID 0x38f8) to convert resources. This csc.exe → cvtres.exe chain is the live compilation of the malicious installer assembly.

**InstallUtil execution (Security EID 4688):** Unfortunately, the Security EID 4688 for `InstallUtil.exe` itself was not captured in the 20-event sample set (the dataset contains 6 total 4688 events in samples). However, Sysmon EID 1 captures a whoami.exe validation at `16:49:38.673` (PID 15968), and the compiler chain confirms the assembly was built. The presence of `csc.exe` and `cvtres.exe` process creates from a PowerShell parent is itself the core artifact trail.

**Compiler chain artifacts (Security EID 4688):**
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (PID 0x4428) spawned by PowerShell (0x4594)
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe` (PID 0x38f8) spawned by csc.exe (0x4428)

**Application log entries:** Two `Application EID 15` events record "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — routine Defender state reporting that occurs despite Defender being disabled via Group Policy. One `Application EID 16384` records the Software Protection service scheduling a restart. These are background OS events.

**Task Scheduler EID 140:** The Software Protection Platform task (`\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`) was updated — correlated with the Application EID 16384. This is unrelated Windows license management activity.

**Sysmon EID 13 registry:** One registry value set event records `svchost.exe` writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index` — the Task Scheduler cache entry update. Unrelated to InstallUtil.

**Process access events (Sysmon EID 10):** PowerShell (PID 16208) opened child processes with full access rights, consistent with the test framework monitoring pattern.

## What This Dataset Does Not Contain

The `InstallUtil.exe` process creation event itself is absent from the 20-event Sysmon sample (though Security 4688 may contain it — 6 events are sampled from 7 total, and InstallUtil.exe would be the seventh). More critically:

- No file creation events for `T1218.004.dll` (the compiled assembly dropped to `%TEMP%`). The 13 Sysmon EID 11 events in the total dataset contain these, but all fall outside the 20-event sample window.
- No `InstallUtil.exe` image load events showing the assembly being loaded
- No evidence of the constructor code executing

## Assessment

This test successfully executed. The full compilation chain — PowerShell spawning `csc.exe` spawning `cvtres.exe` — is captured, proving that the assembly was dynamically compiled. In the defended variant (60 Sysmon, 14 Security, 39 PowerShell events), the compilation chain is also present, meaning Defender does not block the compilation itself. The key difference is in the Sysmon EID 11 count: 13 file creation events here vs. the defended variant's larger EID 7 count, reflecting the difference in DLL load monitoring when Defender is active.

The `CheckIfInstallable` method test path means `InstallUtil.exe` was invoked without `/U` or a full install — it performs a validation pass that still executes the constructor. The expected output `Constructor_` (from the test framework) confirms the constructor ran.

## Detection Opportunities Present in This Data

**`csc.exe` spawned by PowerShell, immediately followed by `cvtres.exe` (Security EID 4688, Sysmon EID 1):** The chain PowerShell → csc.exe → cvtres.exe indicates in-memory or on-disk assembly compilation. In most enterprise environments, PowerShell compiling C# assemblies at runtime is rare and warrants investigation, particularly when running as SYSTEM from `C:\Windows\TEMP\`.

**`InstallUtil.exe` executing a `.dll` from `%TEMP%` (Security EID 4688):** When visible, the command line `InstallUtil.exe /logfile= /logtoconsole=false C:\Windows\TEMP\T1218.004.dll` (expected pattern) directly identifies abuse. The `/logfile=` flag with an empty value suppresses the installation log, a common evasion behavior.

**Compiler chain timing correlation:** The time gap between `csc.exe` execution and a subsequent `InstallUtil.exe` execution (compiling then immediately running) is a behavioral sequence that distinguishes technique abuse from legitimate development activity.

**Sysmon EID 11 — `.dll` files created in `%TEMP%` by PowerShell:** File creation events for `.dll` files written to `%TEMP%` by PowerShell are a reliable precursor to InstallUtil-based execution. While not in the sample set here, the dataset's 13 EID 11 events include them.
