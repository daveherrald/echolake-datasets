# T1564.001-9: Hidden Files and Directories — Create Windows Hidden File with PowerShell

## Technique Context

MITRE ATT&CK T1564.001 (Hidden Files and Directories) includes all methods for marking files with hidden attributes. This test applies the Hidden attribute using the PowerShell .NET file object model rather than the `attrib.exe` command-line tool:

```powershell
$file = Get-Item $env:temp\T1564.001-9.txt -Force
$file.attributes='Hidden'
```

The `-Force` parameter is required to retrieve an item that may already have hidden attributes. Setting `$file.attributes='Hidden'` directly modifies the `FileAttributes` property via the .NET `System.IO.FileInfo` object, which internally calls `SetFileAttributes`. This approach bypasses `attrib.exe` entirely and produces a different process execution footprint.

From a detection standpoint, this variant is more evasive than the attrib.exe approach (T1564.001-4) because no child process is spawned. The entire operation occurs within the PowerShell process itself.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:21:11–14:21:16 UTC).

**Process execution chain (Sysmon EID 1):**

The PowerShell process create record shows the complete attack payload in the command line:

```
"powershell.exe" & {$file = Get-Item $env:temp\T1564.001-9.txt -Force
$file.attributes='Hidden'}
```

The multiline script is preserved verbatim in the process create event, including the newline between the two statements. No cmd.exe or attrib.exe was spawned.

**PowerShell EID 4104 (Script Block Logging):** The script block content is captured twice — once wrapped in the outer ART invocation context and once as the inner script block itself:

```
& {$file = Get-Item $env:temp\T1564.001-9.txt -Force
$file.attributes='Hidden'}

{$file = Get-Item $env:temp\T1564.001-9.txt -Force
$file.attributes='Hidden'}
```

A profile script block from `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` was also logged when PowerShell loaded the SYSTEM profile on startup.

**Security EID 4688:** powershell.exe and whoami.exe process creates, both as SYSTEM. No attrib.exe, cmd.exe, or net.exe is present.

**Sysmon EID 7 (Image Load):** DLL loads for the PowerShell instance.

**Sysmon EID 17 (Pipe Created):** Named pipe for the PowerShell host.

**Sysmon EID 10 (Process Access):** PowerShell accessing whoami.exe.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` test framework invocation.

## What This Dataset Does Not Contain (and Why)

**No attrib.exe process create:** The attribute modification is entirely in-process via the PowerShell .NET API. This is the defining feature of this test variant.

**No Sysmon EID 13 (Registry Value Set):** No registry modifications occur.

**No Sysmon EID 1 for attrib.exe:** The sysmon-modular include rule matching attrib.exe does not fire because attrib.exe is never invoked. Only the PowerShell process itself is captured by the ProcessCreate include rules.

**No file attribute change event:** As noted for T1564.001-4, Windows does not log `SetFileAttributes` API calls. The only record of the hidden attribute being set is the PowerShell command text.

**Object access auditing is disabled:** No file object events.

## Assessment

The PowerShell-based approach produces a cleaner, smaller telemetry footprint compared to the attrib.exe approach. There is no child process tree, and the operation is not flagged by the sysmon-modular T1564.001 attrib.exe rule. However, because PowerShell script block logging is enabled, the complete payload is captured in EID 4104 regardless. The command line in Sysmon EID 1 also exposes the full script text, including the target filename `T1564.001-9.txt`.

This dataset provides a useful contrast with T1564.001-4: the same end result (a hidden file), achieved via two different execution methods, with different process-level footprints but equivalent PowerShell log visibility.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script block containing `$file.attributes='Hidden'` or `$file.attributes='System'`. Setting file attributes via the .NET file object model is a reliable behavioral indicator when the target path is in a temp or user-writable directory.
- **PowerShell EID 4104:** `Get-Item` invoked with `-Force` flag on a temp path, followed by `.attributes=` assignment in the same script block, is a specific pattern that can be detected without regex tuning.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `$file.attributes` or `Get-Item ... -Force` with an attributes assignment.
- **Comparison with T1564.001-4:** A detection that only looks for `attrib.exe` executions will miss this variant entirely. Unified detection across both the process execution path (attrib.exe) and the PowerShell API path (.attributes assignment) is needed for complete coverage.
- **Gap:** If the attacker uses `[System.IO.File]::SetAttributes()` or P/Invoke to `SetFileAttributes` directly, even the PowerShell script block text would differ. The principle — looking for attribute-setting operations on non-system paths — should be generalized.
