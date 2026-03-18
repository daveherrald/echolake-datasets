# T1036.005-3: Match Legitimate Resource Name or Location — Masquerading cmd.exe as VEDetector.exe

## Technique Context

T1036.005 (Match Legitimate Resource Name or Location) is a masquerading technique where adversaries rename malicious files or copy legitimate files to deceptive locations to appear benign. This specific test copies `cmd.exe` to `VEDetector.exe` in the TEMP directory, mimicking a legitimate security tool name. Real-world attackers frequently use this technique to evade security tools that rely on filename-based detection or to blend in with legitimate administrative tools. The detection community focuses on identifying process execution from unexpected locations, monitoring for file copies of system binaries, and analyzing process metadata inconsistencies between filename and actual executable content.

## What This Dataset Contains

The dataset captures the complete masquerading technique execution through multiple telemetry sources. PowerShell events show the technique's implementation via script block logging (EID 4104) with the full command: `Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination "$env:TEMP\VEDetector.exe" -Force`. PowerShell command invocation logs (EID 4103) detail each cmdlet execution including `Copy-Item`, `New-ItemProperty` for registry persistence, and `Start-Process` to launch the masqueraded binary.

Sysmon provides rich process and file telemetry. The file creation event (EID 11) shows `C:\Windows\Temp\VEDetector.exe` being created, while the file executable detection event (EID 29) captures the binary's hash values confirming it's actually `cmd.exe`. Process creation events (EID 1) reveal the masqueraded execution with `Image: C:\Windows\Temp\VEDetector.exe` but `OriginalFileName: Cmd.Exe`, exposing the deception. Registry modification (EID 13) captures persistence establishment at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VEDetector`.

Security events complement this with process creation/termination logs (EID 4688/4689) showing the full process chain and command lines, including the renamed binary execution.

## What This Dataset Does Not Contain

The dataset lacks network-based indicators since this technique is primarily file system and process-based. File system audit events beyond Sysmon's scope aren't captured, which could provide additional file operation context. The technique completed successfully without Windows Defender intervention, so there are no blocked execution events or security product alerts. Some intermediate file operations during the copy process may not be fully captured depending on timing.

## Assessment

This dataset provides excellent coverage for detecting T1036.005 masquerading techniques. The combination of PowerShell script block logging, Sysmon file/process events, and Security audit logs creates multiple detection opportunities. The presence of both the deceptive filename and the true original filename in process metadata is particularly valuable. The registry persistence component adds another detection vector. The data quality is high with complete process chains, command lines, and file hashes captured throughout the execution timeline.

## Detection Opportunities Present in This Data

1. **Process filename/original filename mismatch** - Sysmon EID 1 shows `Image: C:\Windows\Temp\VEDetector.exe` but `OriginalFileName: Cmd.Exe`, indicating masquerading of a system binary

2. **System binary execution from non-standard locations** - cmd.exe (identified by hash/original filename) executing from `C:\Windows\Temp\` instead of `System32`

3. **File copy operations of system binaries** - PowerShell `Copy-Item` commands targeting system executables like `cmd.exe` to user-writable directories

4. **Executable file creation in temp directories** - Sysmon EID 11 and 29 showing `.exe` files created in `C:\Windows\Temp\` with system binary hashes

5. **Registry Run key persistence with suspicious filenames** - Registry modifications creating autorun entries for files in temporary directories, especially with security tool-like names

6. **PowerShell script blocks containing masquerading operations** - Script block logging capturing copy operations of system binaries combined with persistence mechanisms

7. **Process hash correlation** - Correlating process hashes against known system binaries to identify renamed legitimate tools in unexpected locations
