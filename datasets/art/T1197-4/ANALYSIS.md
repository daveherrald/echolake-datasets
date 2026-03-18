# T1197-4: BITS Jobs — Bits download using desktopimgdownldr.exe (cmd)

## Technique Context

BITS Jobs (T1197) is a defense evasion and persistence technique where adversaries abuse the Windows Background Intelligent Transfer Service to download, execute, or clean up after running malicious code. BITS is a legitimate Windows service designed for asynchronous file transfers that can operate with limited bandwidth and resume interrupted transfers. Adversaries often leverage BITS through legitimate Windows utilities like bitsadmin.exe or through alternative methods that interact with the BITS infrastructure.

This specific test demonstrates abuse of `desktopimgdownldr.exe`, a lesser-known Windows utility that can trigger BITS downloads. The detection community focuses on monitoring BITS job creation, unexpected processes spawning BITS-related activities, network connections from BITS utilities, and file downloads to unusual locations.

## What This Dataset Contains

The dataset captures a PowerShell-initiated command chain that uses `desktopimgdownldr.exe` to perform a BITS download. Key events include:

**Process Creation Chain (Security 4688 and Sysmon 1):**
- PowerShell spawns cmd.exe: `"cmd.exe" /c set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md /eventName:desktopimgdownldr`
- Second cmd.exe: `cmd /c desktopimgdownldr.exe /lockscreenurl:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md /eventName:desktopimgdownldr`
- Final execution: `desktopimgdownldr.exe /lockscreenurl:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md /eventName:desktopimgdownldr`

**Process Exit Status:** The desktopimgdownldr.exe process (PID 37688) exits with status `0xFFFFFFFF`, indicating an error condition, suggesting the download attempt may have failed.

**Environment Manipulation:** The command sets `SYSTEMROOT=C:\Windows\Temp` before execution, potentially attempting to redirect system behavior.

**DLL Loading:** Sysmon captures urlmon.dll loading into desktopimgdownldr.exe, which is expected for URL-based download functionality.

## What This Dataset Does Not Contain

The dataset lacks several critical elements for complete BITS analysis:

**No BITS-specific Events:** Windows doesn't generate specific event IDs for BITS job creation or completion in the standard channels collected here. BITS events typically appear in Microsoft-Windows-Bits-Client/Operational, which wasn't captured.

**No Network Events:** Despite the URL parameter indicating an attempted download, no Sysmon Event ID 3 (NetworkConnect) events appear, likely because the operation failed before establishing connections.

**No File Creation Events:** The expected downloaded file creation isn't captured, consistent with the error exit status suggesting download failure.

**No WinINet/URLMon Events:** While urlmon.dll loads, there are no associated network activity logs showing the actual HTTP request attempts.

## Assessment

This dataset provides limited utility for detection engineering focused on successful BITS abuse. The primary value lies in capturing the process execution chain leading to `desktopimgdownldr.exe` usage, which is valuable for identifying this specific BITS abuse vector. However, the apparent failure of the actual download operation (evidenced by the 0xFFFFFFFF exit code) means the dataset lacks the network and file system artifacts that would typically accompany successful BITS downloads.

For comprehensive BITS detection development, analysts would need additional log sources including Microsoft-Windows-Bits-Client/Operational events and successful execution examples. The dataset is most useful for understanding the process-level indicators of this particular BITS abuse technique rather than the complete attack lifecycle.

## Detection Opportunities Present in This Data

1. **Rare Binary Execution Detection** - Monitor for execution of `desktopimgdownldr.exe` with suspicious URL parameters, particularly from non-standard parent processes like PowerShell or cmd.exe

2. **Command Line Pattern Detection** - Alert on command lines containing `desktopimgdownldr.exe` with `/lockscreenurl:` parameters pointing to external URLs, especially non-Microsoft domains

3. **Process Chain Analysis** - Detect PowerShell spawning cmd.exe chains that ultimately execute `desktopimgdownldr.exe`, indicating potential Living Off the Land Binary (LOLBin) abuse

4. **Environment Variable Manipulation** - Monitor for `SYSTEMROOT` environment variable modification in conjunction with suspicious binary execution

5. **URLMON.dll Loading Context** - Alert on urlmon.dll loading into unexpected processes like `desktopimgdownldr.exe` when executed from suspicious parent processes

6. **Process Exit Code Monitoring** - Track failed executions (0xFFFFFFFF exit status) of BITS-related utilities as potential indicators of blocked or failed attack attempts

7. **Working Directory Analysis** - Flag execution of `desktopimgdownldr.exe` from non-standard directories like `C:\Windows\Temp\`
