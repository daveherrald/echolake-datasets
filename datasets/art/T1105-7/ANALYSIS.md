# T1105-7: Ingress Tool Transfer — certutil download (urlcache)

## Technique Context

T1105 Ingress Tool Transfer involves adversaries bringing tools or files into a compromised environment from external systems. Certutil.exe is a legitimate Windows certificate services utility that also includes functionality to download files from URLs using its `-urlcache` parameter. This technique is popular among attackers because certutil is a signed Microsoft binary present on all Windows systems, making it an effective Living Off The Land Binary (LOLBin) for file downloads.

The detection community focuses on monitoring certutil usage with network-related parameters (`-urlcache`, `-verifyctl`, `-syncwithws`), especially when downloading from suspicious domains or IP addresses. Key detection points include process creation events with certutil command lines containing these parameters, network connections to external hosts, and file creation events for downloaded payloads.

## What This Dataset Contains

This dataset captures a certutil download attempt that was blocked by Windows Defender. The primary evidence appears in Security event 4688, which shows the command execution:

```
Process Command Line: "cmd.exe" /c cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt
```

The technique execution shows PowerShell (PID 9892) spawning cmd.exe (PID 39692) which then attempts to execute the certutil command. However, the cmd.exe process exits with status code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

Sysmon captures the PowerShell process activity, including:
- Process creation for whoami.exe (EID 1) - likely test framework verification
- Image loads for PowerShell's .NET runtime components (EIDs 7)
- Windows Defender DLL loads (MpOAV.dll, MpClient.dll) showing active protection
- Process access and remote thread creation events (EIDs 10, 8) from PowerShell execution
- Named pipe creation for PowerShell host communication (EID 17)
- File creation events for PowerShell profile data (EID 11)

The PowerShell channel contains only boilerplate test framework activity (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) with no evidence of the actual certutil command execution.

## What This Dataset Does Not Contain

This dataset lacks the successful execution telemetry that would normally accompany this technique because Windows Defender blocked the certutil process before it could execute. Missing elements include:

- **Certutil process creation** - No Sysmon EID 1 or Security 4688 for certutil.exe itself
- **Network connection events** - No Sysmon EID 3 showing HTTPS connection to raw.githubusercontent.com
- **DNS resolution** - No Sysmon EID 22 for domain name lookup
- **Downloaded file creation** - No file system events for the target file "Atomic-license.txt"
- **Certutil cache operations** - No evidence of URL cache manipulation or file retrieval

The sysmon-modular configuration's include-mode filtering for ProcessCreate events means we wouldn't necessarily see the cmd.exe process creation in Sysmon (it appears only in Security 4688), but we would expect to see certutil.exe if it had been allowed to execute, as it matches LOLBin detection patterns.

## Assessment

This dataset provides excellent evidence of Windows Defender's real-time protection capabilities against LOLBin abuse, but limited value for detection engineering of successful certutil-based file downloads. The Security channel provides complete command-line visibility of the attempted execution, making it valuable for detecting the attack attempt itself.

For building detections of this technique, the dataset demonstrates that Security 4688 events are crucial when endpoint protection blocks execution before Sysmon can capture the full process chain. The blocked execution with status code 0xC0000022 serves as a clear indicator of attempted malicious activity that was prevented.

## Detection Opportunities Present in This Data

1. **Certutil command line detection** - Security EID 4688 with command lines containing "certutil" and URL-related parameters (`-urlcache`, `-split`, `-f`) followed by HTTP/HTTPS URLs

2. **Blocked process execution analysis** - Security EID 4689 events with exit status 0xC0000022 (STATUS_ACCESS_DENIED) indicating endpoint protection intervention

3. **LOLBin execution through cmd.exe** - Process creation chains where cmd.exe spawns with command lines executing known LOLBins like certutil with suspicious parameters

4. **PowerShell to cmd.exe process spawning** - Detection of PowerShell processes creating cmd.exe children, especially with complex command lines containing multiple command separators

5. **Windows Defender DLL loading patterns** - Sysmon EID 7 events showing MpOAV.dll and MpClient.dll loads in processes attempting suspicious activities, indicating active scanning

6. **GitHub raw content downloads** - Command lines referencing "raw.githubusercontent.com" or other code repository raw content URLs in certutil or similar utilities
