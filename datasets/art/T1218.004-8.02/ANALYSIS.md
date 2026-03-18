# T1218.004-8: InstallUtil — InstallUtil Evasive Invocation

## Technique Context

T1218.004 (InstallUtil) describes abusing `InstallUtil.exe` to execute malicious .NET assemblies. Test 8 takes this a step further with an evasive invocation strategy: instead of calling `InstallUtil.exe` by its real name and path, the technique copies `InstallUtil.exe` to a different location under a different name, and executes the renamed copy against an assembly disguised as a `.txt` file. This defeats detection controls that specifically look for `InstallUtil.exe` by image name, hash, or path.

The three evasion dimensions in this test are:
1. `InstallUtil.exe` is copied to `C:\Windows\System32\Tasks\notepad.exe` — a location with a trusted Windows system path prefix but the name of a known harmless utility
2. The malicious assembly is written as `C:\Windows\System32\Tasks\readme.txt` — a filename that suggests a text document, not a .NET assembly
3. `notepad.exe` (the renamed InstallUtil.exe) is invoked with a relative path to `readme.txt`

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17T16:50:11Z to 16:50:16Z) across 199 total events: 106 PowerShell, 9 Security, 84 Sysmon.

**Full evasive technique command (Security EID 4688):** The child PowerShell process (PID 0x47dc / 18396) received the test framework script, captured in full in its Security EID 4688 process creation record:

```powershell
$InstallerAssemblyDir = "$Env:windir\System32\Tasks\"
$InstallerAssemblyFileName = 'readme.txt'
$CommandLine = "readme.txt"
# Explicitly set the directory so that a relative path to readme.txt can be supplied.
Set-Location "$Env:windir\System32\Tasks\"
Copy-Item -Path "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())InstallUtil.exe" -Destination "$Env:windir\System32\Tasks\notepad.exe"
$TestArgs = @{
    InstallUtilPath = "$Env:windir\System32\Tasks\notepad.exe"
    [...]
}
$ExpectedOutput = 'Constructor_'
```

**Renamed InstallUtil.exe executing a .txt assembly (Security EID 4688):** The renamed binary launched as:

```
"C:\Windows\System32\Tasks\notepad.exe" readme.txt
```

PID 0x41d4, spawned by PowerShell (0x47dc). The image name is `notepad.exe`, the path is `C:\Windows\System32\Tasks\`, and the argument is a bare filename with no extension indicating a binary. This is the evasion in action.

**Cleanup (Security EID 4688 and PS EID 4104):** The cleanup PowerShell block recorded in EID 4104 shows the artifacts removed post-execution:

```powershell
Remove-Item -Path "$Env:windir\System32\Tasks\readme.txt" -ErrorAction Ignore
Remove-Item -Path "$Env:windir\System32\Tasks\readme.InstallLog" -ErrorAction Ignore
Remove-Item -Path "$Env:windir\System32\Tasks\readme.InstallState" -ErrorAction Ignore
Remove-Item -Path "$Env:windir\System32\Tasks\notepad.exe" -ErrorAction Ignore
```

The cleanup block names the full artifact list: `readme.txt` (the assembly), `readme.InstallLog` and `readme.InstallState` (InstallUtil runtime files), and `notepad.exe` (the renamed binary). These file paths are ground truth for what was written to `C:\Windows\System32\Tasks\`.

**Double csc.exe compilation (Security EID 4688):** Two csc.exe (PIDs 0x4488 and 0x41d0) and two cvtres.exe (PIDs 0x4504 and 0x3d0c) processes are recorded — the same dual-pass compilation pattern as T1218.004-3 and T1218.004-5.

**Sysmon EID breakdown:** 84 total Sysmon events with 27 EID 11 (file creation) events — the highest file creation count in the T1218.004 series, reflecting the additional writes to `C:\Windows\System32\Tasks\` for the renamed binary and disguised assembly. EID 22 (4 DNS events), EID 29 (2 events), and EID 26 (1 event) are also present in the totals but fall outside the sample window.

## What This Dataset Does Not Contain

The file creation events for `readme.txt`, `notepad.exe`, `readme.InstallLog`, and `readme.InstallState` in `C:\Windows\System32\Tasks\` are all in the 27 EID 11 events in the total dataset but outside the 20-event Sysmon sample. Sysmon EID 29 (2 events) and EID 26 (1 event) in the full dataset indicate file delete operations — likely the cleanup — but these are also outside the sample.

## Assessment

This is a fully successful evasive InstallUtil execution. The evasion strategy is completely documented in the Security EID 4688 command line, which captures the test framework script verbatim — a reminder that PowerShell script block arguments to child processes appear in the Security 4688 record even when the scripts themselves are not logged in the PowerShell channel.

Comparing with the defended variant (76 Sysmon, 20 Security, 39 PowerShell events): both runs successfully execute the technique. The undefended run generates more PowerShell instrumentation (106 vs. 39) without AMSI. The higher Sysmon event count in the defended variant (84 vs. 76 undefended, approximately equal) reflects similar DLL load and file creation activity in both configurations — Defender does not appear to block this evasive path.

The most significant insight from this dataset is how the evasion strategy shifts the detection problem: an analyst looking for `InstallUtil.exe` by name or `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe` by path will not find the actual execution event. Instead, detection must rely on behavioral indicators — `notepad.exe` in an unexpected path, assembly compilation from PowerShell, or file system artifacts in `C:\Windows\System32\Tasks\`.

## Detection Opportunities Present in This Data

**`notepad.exe` executing from `C:\Windows\System32\Tasks\` (Security EID 4688, Sysmon EID 1):** `notepad.exe` is a well-known binary whose legitimate path is `C:\Windows\System32\notepad.exe` or `C:\Windows\notepad.exe`. Any instance of `notepad.exe` executing from `C:\Windows\System32\Tasks\` is immediately suspicious. This extends to any well-known binary name appearing in an unexpected path.

**PowerShell `Copy-Item` from the .NET Framework runtime directory into a system tasks directory (Security EID 4688):** The test framework command explicitly copies `InstallUtil.exe` from `[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()` — a programmatic way to find the .NET runtime path. PowerShell scripts that copy binaries from .NET Framework directories to System32 subdirectories deserve close scrutiny.

**Assembly written to `C:\Windows\System32\Tasks\` with a `.txt` extension (Sysmon EID 11):** Writing files to `C:\Windows\System32\Tasks\` is unusual in itself — this directory normally contains only XML task definition files. A file named `readme.txt` created there by PowerShell is a behavioral anomaly, regardless of whether you know it is a .NET assembly.

**InstallUtil log files (`*.InstallLog`, `*.InstallState`) in non-standard locations (Sysmon EID 11):** `InstallUtil.exe` writes `readme.InstallLog` and `readme.InstallState` alongside the target assembly. When these files appear outside of application installation directories (e.g., in `C:\Windows\System32\Tasks\`), their presence reveals that something functioning as InstallUtil executed in that location, even if the binary itself was renamed.

**Double csc.exe compilation from PowerShell running as SYSTEM (Security EID 4688):** Same behavioral signature as other T1218.004 tests — the compilation chain is a consistent precursor to all InstallUtil abuse scenarios in this series, regardless of evasion strategy.
