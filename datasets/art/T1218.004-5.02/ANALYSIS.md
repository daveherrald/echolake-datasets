# T1218.004-5: InstallUtil — InstallUtil Uninstall Method Call (/U Variant)

## Technique Context

T1218.004 (InstallUtil) abuses `InstallUtil.exe`, the .NET Framework installation utility, to execute code in malicious assemblies. While most InstallUtil abuse discussions focus on the install phase, the `/U` (uninstall) flag also invokes managed code — specifically the `Uninstall()` method of the installer class, as well as the class constructor. This variant is notable because some detection rules specifically look for InstallUtil without the `/U` flag, making the uninstall path a potential bypass of narrowly-scoped controls.

This test uses the `Invoke-BuildAndInvokeInstallUtilAssembly` test framework from AtomicTestHarnesses. The assembly is compiled to `C:\Windows\TEMP\T1218.004.dll`, and `InstallUtil.exe` is invoked with `/logfile= /logtoconsole=false /U` followed by the assembly path. The expected output `Constructor_Uninstall_` confirms both the constructor and the Uninstall method executed.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17T16:50:00Z to 16:50:05Z) across 178 total events: 102 PowerShell, 9 Security, 67 Sysmon.

**Full technique command (Security EID 4688):** The child PowerShell process (PID 0x4490 / 18640) received the full test framework script. The Security EID 4688 command line reads:

```
"powershell.exe" & {# Import the required test framework function, Invoke-BuildAndInvokeInstallUtilAssembly
. "C:\AtomicRedTeam\atomics\T1218.004\src\InstallUtilTestHarness.ps1"
$InstallerAssemblyDir = "$Env:TEMP\"
$InstallerAssemblyFileName = "T1218.004.dll"
$CommandLine = "/logfile= /logtoconsole=false /U `"$InstallerAssemblyFullPath`""
$ExpectedOutput = 'Constructor_Uninstall_'
[...]
$ActualOutput = Invoke-BuildAndInvokeInstallUtilAssembly @TestArgs
```

**InstallUtil.exe uninstall invocation (Security EID 4688):** `InstallUtil.exe` (PID 0x3ea4) was spawned by the child PowerShell (PID 0x4490), with the command line:

```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false /U C:\Windows\TEMP\T1218.004.dll
```

The `/U` flag distinguishes this from the install-phase variants (T1218.004-3, T1218.004-1). This is the definitive uninstall execution event.

**Compilation chain (Security EID 4688):** Two csc.exe → cvtres.exe compilation cycles are recorded (PIDs 0x46a0/0x44f0 for csc.exe, 0x4638/0x2ff8 for cvtres.exe), matching the dual-pass pattern seen in T1218.004-3. The assembly was dynamically compiled from the test framework PowerShell session.

**Image loads (Sysmon EID 7, 26 total):** The full .NET runtime DLL load pattern is present in both the test framework PowerShell and InstallUtil.exe processes. The 26 EID 7 events reflect the assembly loading into the InstallUtil.exe process context for uninstall phase execution.

**Process access events (Sysmon EID 10, 8 total):** Cross-process open events from PowerShell to child processes with full access rights, consistent with test framework monitoring behavior.

**Named pipe creation (Sysmon EID 17, 3 total):** PowerShell host pipes confirm the test framework and cleanup phases ran in separate PowerShell sessions.

## What This Dataset Does Not Contain

As with T1218.004-3, the file creation events for `T1218.004.dll` being written to `%TEMP%` are not in the 20-event Sysmon sample (the 67 total Sysmon events include 23 EID 11 events). The `Uninstall()` method's code execution is not directly logged — the `Constructor_Uninstall_` output exists only in stdout.

## Assessment

This is a fully successful InstallUtil uninstall execution. The complete chain — test framework script in the PowerShell command line, two compilation cycles, and `InstallUtil.exe` with the `/U` flag against `%TEMP%\T1218.004.dll` — is all present. The Security EID 4688 records provide unambiguous evidence of the technique.

The `/U` variant produces telemetry nearly identical to T1218.004-3 (constructor only), with the sole explicit distinction being `/U` in the InstallUtil.exe command line. Both tests produce the same compiler chain and file artifacts. The key difference for detection is that rules must account for the `/U` flag path, not just the default install path.

Comparing with the defended variant (66 Sysmon, 20 Security, 39 PowerShell events): the core chain is present in both. The undefended run's higher PowerShell event count (102 vs. 39) reflects the absence of AMSI filtering on script block content. The defended run has more Security events (20 vs. 9) due to additional process creation events captured when Defender components are involved.

## Detection Opportunities Present in This Data

**`InstallUtil.exe /U` with `/logfile=` suppression processing a `.dll` from `%TEMP%` (Security EID 4688):**

```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /logfile= /logtoconsole=false /U C:\Windows\TEMP\T1218.004.dll
```

Detection logic that only looks for InstallUtil without `/U` misses this variant. The `/U` flag explicitly enables the uninstall code path, which invokes both constructor and `Uninstall()` method — potentially doubling the code execution surface compared to the install path.

**Double csc.exe compilation from PowerShell (Security EID 4688):** The same dual-pass compilation signature as T1218.004-3 is present here. Two csc.exe processes from the same PowerShell parent, each spawning cvtres.exe, indicate the test framework's full assembly preparation workflow.

**`InstallUtil.exe` spawned directly by PowerShell as SYSTEM from `%TEMP%` (Security EID 4688):** The parent-child relationship and execution context (SYSTEM, working directory `C:\Windows\TEMP\`) are reliable behavioral anchors. Legitimate uninstall operations using InstallUtil.exe are typically invoked by setup packages with proper working directories and explicit log paths.

**Correlation of csc.exe compilation followed by InstallUtil.exe targeting the compiled artifact:** When a Security EID 4688 for csc.exe is followed within seconds by an InstallUtil.exe event targeting a same-named output file from `%TEMP%`, the sequence constitutes a high-confidence technique indicator regardless of whether `/U` or a direct install path is used.
