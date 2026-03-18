# T1059.001-11: PowerShell — NTFS Alternate Data Stream Access

## Technique Context

T1059.001 (PowerShell) is a critical execution technique where adversaries leverage PowerShell to execute commands, scripts, and binaries. This specific test demonstrates a particularly stealthy variant: using NTFS Alternate Data Streams (ADS) to hide and execute PowerShell code. ADS allows data to be attached to files without changing their apparent size or modification time, making it an attractive technique for persistence, data hiding, and defense evasion.

Attackers commonly use ADS for storing malicious payloads, configuration data, or scripts that can be executed without creating obvious file artifacts. The technique combines T1059.001 (PowerShell execution) with aspects of T1564.004 (NTFS File Attributes) and T1027 (Obfuscated Files or Information). Detection engineers focus on monitoring ADS creation, PowerShell cmdlets that interact with streams (`Add-Content -Stream`, `Get-Content -Stream`), and the execution of content retrieved from alternate data streams.

## What This Dataset Contains

The dataset captures a complete NTFS ADS PowerShell execution sequence. The Security channel shows PowerShell process creation with the full command line: `"powershell.exe" & {Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host \"Stream Data Executed\"' -Stream 'streamCommand'...}`. 

Sysmon provides rich process and file activity telemetry. EID 1 events capture the PowerShell process creation with `CommandLine` showing the complete ADS manipulation script. EID 15 events document the alternate data stream creation at `C:\Windows\Temp\NTFS_ADS.txt:streamCommand` with the actual stream contents: `"Write-Host \"Stream Data Executed\""`. EID 11 events show file creation for both the main file and the ADS file.

The PowerShell operational logs contain extensive script block logging (EID 4104) capturing the exact execution flow: `Add-Content` writing to the stream, `Get-Content` reading from the stream, `Invoke-Expression` executing the retrieved content, and the final `Write-Host` command execution. Module logging (EID 4103) provides detailed parameter bindings for each cmdlet, including the `-Stream 'streamCommand'` parameter that indicates ADS usage.

## What This Dataset Does Not Contain

The dataset lacks file system monitoring beyond Sysmon's capabilities. There are no ETW FileIO events or detailed file access patterns that might show ADS enumeration activities. The technique executed successfully without any EDR or AMSI blocks, so there are no prevention/quarantine events.

No network activity is present since this is a local file-based technique. Registry modifications related to PowerShell execution policy are not captured in this specific dataset, though the Security logs show successful execution. The dataset also doesn't contain any cleanup activities - the ADS file remains on disk after execution.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based NTFS ADS abuse. The combination of Security 4688 events (with command-line logging), Sysmon file creation events (EIDs 11 and 15), and comprehensive PowerShell logging creates multiple detection opportunities. The EID 15 events are particularly valuable as they specifically capture alternate data stream creation with content hashes.

The PowerShell script block logging captures the complete attack chain, from ADS creation through content retrieval and execution. This level of detail enables both signature-based and behavioral detection approaches. The presence of both process-level and file-level telemetry makes this dataset suitable for developing robust detection rules.

## Detection Opportunities Present in This Data

1. **ADS Creation Detection**: Monitor Sysmon EID 11 events for file creation with colon-separated filenames (e.g., `NTFS_ADS.txt:streamCommand`) indicating alternate data stream creation

2. **PowerShell ADS Cmdlet Usage**: Alert on PowerShell EID 4103 command invocations of `Add-Content` or `Get-Content` with `-Stream` parameters in the command line

3. **Script Block ADS Pattern**: Detect PowerShell EID 4104 script blocks containing both `Add-Content -Stream` and `Get-Content -Stream` operations in sequence, especially when followed by `Invoke-Expression`

4. **Process Command Line ADS Indicators**: Hunt for Security EID 4688 or Sysmon EID 1 events with PowerShell command lines containing `-Stream` parameters combined with `Invoke-Expression`

5. **File Stream Creation Events**: Monitor Sysmon EID 15 events for alternate data stream creation, particularly when the stream contains executable content (PowerShell commands, scripts, or encoded payloads)

6. **Temporal Correlation**: Correlate rapid sequence of ADS file creation (EID 11), content writing (EID 15), content reading (PowerShell module logs), and execution (script blocks) within short time windows

7. **Suspicious Stream Names**: Flag creation of ADS with non-standard stream names (anything other than default NTFS streams) combined with PowerShell execution context
