# T1564.001-10: Hidden Files and Directories — Create Windows System File with PowerShell

## Technique Context

MITRE ATT&CK T1564.001 (Hidden Files and Directories) covers all methods for applying hiding attributes to files. This test is the PowerShell API equivalent of T1564.001-3 (attrib.exe `+s`). Rather than invoking `attrib.exe`, it sets the System attribute directly via the PowerShell .NET file object model:

```powershell
$file = Get-Item $env:temp\T1564.001-10.txt -Force
$file.attributes='System'
```

Files marked with the System attribute are treated as protected operating system files by Windows Explorer and many security tools. When combined with the registry modifications from T1564.001-8 (setting `ShowSuperHidden = 0`), system-attributed files become invisible to standard user-level and many analyst-level directory inspection methods.

The PowerShell API approach avoids spawning `attrib.exe`, removing the process execution indicator that sysmon-modular's T1564.001 include rule is designed to catch.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:21:33–14:21:38 UTC).

**Process execution chain (Sysmon EID 1):**

The PowerShell process create record captures the full payload:

```
"powershell.exe" & {$file = Get-Item $env:temp\T1564.001-10.txt -Force
$file.attributes='System'}
```

The multiline script is preserved verbatim, including the newline between statements. No child process is spawned.

**PowerShell EID 4104 (Script Block Logging):** The script block content is logged in both the outer invocation wrapper and the inner script block:

```
& {$file = Get-Item $env:temp\T1564.001-10.txt -Force
$file.attributes='System'}

{$file = Get-Item $env:temp\T1564.001-10.txt -Force
$file.attributes='System'}
```

The distinction between `'System'` (this test) and `'Hidden'` (T1564.001-9) is the only functional difference. A PowerShell profile script block from the SYSTEM profile was also captured on startup.

**Security EID 4688:** powershell.exe and whoami.exe, both as SYSTEM. Structurally identical to T1564.001-9.

**Sysmon EID 7 (Image Load):** DLL loads for PowerShell startup.

**Sysmon EID 17 (Pipe Created):** Named pipe for the PowerShell host.

**Sysmon EID 10 (Process Access):** PowerShell accessing the whoami.exe child process.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` test framework invocation.

## What This Dataset Does Not Contain (and Why)

**No attrib.exe process create:** The attribute change is entirely in-process via the PowerShell .NET API. The sysmon-modular T1564.001 include rule targeting attrib.exe does not fire.

**No Sysmon EID 13:** No registry writes occur.

**No Sysmon EID 1 for attrib.exe:** For the same reason as T1564.001-9 — attrib.exe is never invoked.

**No file attribute change event:** Windows does not generate security audit events for `SetFileAttributes` API calls.

**Object access auditing is disabled.**

## Assessment

This dataset is structurally identical to T1564.001-9, with `'System'` substituted for `'Hidden'`. The two tests together demonstrate that the same detection logic applies to both attribute types: PowerShell script block logging captures the payload regardless of which specific attribute is being set, while process-level detections (attrib.exe) miss both variants.

The `$file.attributes='System'` pattern in a script block targeting a temp-directory file is the highest-confidence indicator in this dataset. The Sysmon EID 1 command line provides a secondary source of the same information.

Taken alongside T1564.001-3, T1564.001-4, T1564.001-8, and T1564.001-9, this test is the fourth T1564.001 variant in this collection. Together they map a coverage matrix: two attribute types (`+h` and `+s`), two execution methods (`attrib.exe` and PowerShell API), and one registry-level technique (Explorer settings). This dataset and T1564.001-9 represent the PowerShell API variants.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script block containing `$file.attributes='System'`. As with T1564.001-9, the attribute value string `'System'` is present verbatim in the logged script block.
- **PowerShell EID 4104:** The pattern `Get-Item ... -Force` followed by `.attributes=` assignment is a reliable behavioral fingerprint for programmatic attribute manipulation, independent of the specific attribute value.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `$file.attributes` as part of the argument — though argument parsing must handle multiline content.
- **Unified detection:** A single detection rule covering `$file.attributes='Hidden'`, `$file.attributes='System'`, `$file.attributes='Hidden, System'`, and `[System.IO.File]::SetAttributes()` pattern variations provides broader coverage than attribute-specific rules.
- **Gap:** The System attribute change is not independently verifiable from any log source other than the PowerShell command text. If the script block were obfuscated or if the attribute were set using `[System.IO.File]::SetAttributes()` with a numeric value, the plain-text pattern would not match.
