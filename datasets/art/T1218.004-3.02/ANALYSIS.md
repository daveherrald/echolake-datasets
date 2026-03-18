# T1218.004-3: InstallUtil — InstallUtil Class Constructor Method Call

## Technique Context

T1218.004 (InstallUtil) abuses the legitimate `InstallUtil.exe` .NET Framework utility to execute code in malicious .NET assemblies. When `InstallUtil.exe` processes an assembly, it instantiates the installer class — executing the class constructor before any other installer method. The class constructor execution variant focuses on placing attack code in the constructor itself (`Constructor_` is the expected output from this test), which runs before any install or uninstall phase begins.

This test uses the `Invoke-BuildAndInvokeInstallUtilAssembly` test framework from AtomicTestHarnesses with `InvocationMethod = 'Executable'`. The test framework dynamically compiles a .NET assembly to `C:\Windows\TEMP\T1218.004.dll`, then invokes `InstallUtil.exe` against it with the `/logfile= /logtoconsole=false` flags, which suppress log output. The expected output `Constructor_` confirms the constructor executed successfully.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17T16:49:49Z to 16:49:54Z) across 172 total events: 100 PowerShell, 9 Security, 63 Sysmon.

**Full PowerShell technique command (Security EID 4688):** The child PowerShell process (PID 0x44d8 / 17624) received the full test framework script, captured in its Security EID 4688 process creation record. The command line reads:

```
"powershell.exe" & {# Import the required test framework function, Invoke-BuildAndInvokeInstallUtilAssembly
. "C:\AtomicRedTeam\atomics\T1218.004\src\InstallUtilTestHarness.ps1"
$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "T1218.004.dll"
$CommandLine = "/logfile= /logtoconsole=false `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_'
[...]
$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs -MinimumViableAssembly
```

**InstallUtil.exe process creation (Security EID 4688):** `InstallUtil.exe` (PID 0x4704) was spawned by the child PowerShell (PID 0x44d8 / 0x4594 in Security), with the command line:

```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false C:\Windows\TEMP\T1218.004.dll
```

This is the definitive technique execution event — `InstallUtil.exe` processing a `.dll` from `%TEMP%` with log suppression flags.

**Compilation chain (Security EID 4688):** Two csc.exe → cvtres.exe compilation cycles are recorded (PIDs 0x46e0/0x404c for csc.exe, 0x4530/0x9a8 for cvtres.exe). Two compilation passes occur because the test framework first compiles for a pre-check, then compiles the final assembly.

**Sysmon EID 1 — PowerShell with test framework command:** Sysmon EID 1 (PID 17624) carries the truncated test framework command line, confirmed with RuleName `technique_id=T1083,technique_name=File and Directory Discovery` from the sysmon-modular PowerShell command-line include rules.

**Process access events (Sysmon EID 10):** PowerShell (PID 17764) opened child processes (PIDs 16284, 17624, 17856) with full access, tagged `T1055.001` by sysmon-modular.

**Image loads (Sysmon EID 7, 22 total):** The heavy .NET runtime DLL load set — mscoree.dll, mscoreei.dll, clr.dll, mscorlib.ni.dll, System.Management.Automation.ni.dll, clrjit.dll — reflects both the test framework PowerShell and the InstallUtil.exe process loading the .NET runtime to execute the malicious assembly's constructor.

## What This Dataset Does Not Contain

File creation events for `T1218.004.dll` being written to `C:\Windows\TEMP\` are not in the 20-event sample (the total 63 Sysmon events include 24 EID 11 events, all outside the sample window). The constructor's actual code execution is not separately logged — the output `Constructor_` exists only in the test framework's stdout, not in Windows event logs.

## Assessment

This is a fully successful InstallUtil constructor execution. You have the complete chain: test framework PowerShell command line → csc.exe compilation × 2 → cvtres.exe resource conversion × 2 → InstallUtil.exe with the final DLL path and log-suppression flags. The `InstallUtil.exe` command line is precisely what detection rules should target.

In the defended variant (75 Sysmon, 20 Security, 41 PowerShell events), the identical execution chain occurs — meaning Windows Defender does not block the constructor execution path. The defended run's higher Sysmon count (75 vs. 63) reflects more DLL image load events captured; with Defender active, additional Defender-related DLLs load into both powershell.exe and InstallUtil.exe processes.

Compared to T1218.004-1 (CheckIfInstallable), this test explicitly confirms that `InstallUtil.exe` ran to completion with expected output. Both tests write `T1218.004.dll` to `%TEMP%` and call `InstallUtil.exe` with identical flags — the difference is in what the assembly implements (minimal constructor vs. full CheckIfInstallable override).

## Detection Opportunities Present in This Data

**`InstallUtil.exe` with `/logfile=` (empty) and `/logtoconsole=false` processing a `.dll` from `%TEMP%` (Security EID 4688):** This command line pattern is highly specific to technique abuse. Legitimate InstallUtil deployments typically specify log paths, not suppress them, and process assemblies from application installation directories, not `%TEMP%`.

```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false C:\Windows\TEMP\T1218.004.dll
```

**Double csc.exe → cvtres.exe compilation cycle from PowerShell (Security EID 4688):** Two sequential csc.exe compilations from the same PowerShell parent, each followed by cvtres.exe, indicates the test framework's dual-pass compile strategy. While a single compilation cycle is already suspicious, two passes in rapid succession tighten the behavioral signature.

**`InstallUtil.exe` parent process being PowerShell (Security EID 4688):** The direct parent-child relationship PowerShell → InstallUtil.exe is unusual. Legitimate InstallUtil invocations typically originate from MSI packages, deployment scripts with specific installer contexts, or setup executables — not interactive PowerShell sessions running as SYSTEM from `%TEMP%`.

**Large .NET DLL image load count into InstallUtil.exe (Sysmon EID 7):** When InstallUtil.exe loads the full .NET runtime assembly set (mscoree, clr, clrjit, mscorlib) to process a user-supplied DLL, the image load telemetry reflects an active code execution context rather than a simple utility run. Sysmon EID 7 events for InstallUtil.exe loading user assemblies are rare in legitimate environments.
