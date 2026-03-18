# T1202-5: Indirect Command Execution — Indirect Command Execution - RunMRU Dialog

## Technique Context

T1202 Indirect Command Execution involves adversaries using legitimate utilities or processes to execute their malicious commands, effectively "living off the land" to avoid detection. This specific test (T1202-5) demonstrates execution through the Windows Run dialog (RunMRU), which maintains a history of previously executed commands in the registry. Attackers can exploit this mechanism by programmatically opening the Run dialog and sending keystrokes to execute commands, leveraging the Shell.Application COM object's FileRun() method. This technique is particularly evasive because it uses standard Windows GUI components and APIs that appear benign to many detection systems. The detection community focuses on identifying unusual COM object instantiation patterns, programmatic GUI automation (SendKeys), and suspicious process execution chains involving legitimate Windows components.

## What This Dataset Contains

This dataset captures a complete RunMRU dialog execution chain initiated through PowerShell. The attack begins with Security 4688 events showing the initial PowerShell execution: `"powershell.exe" & {# Copy command to clipboard Set-Clipboard -Value 'calc.exe'...}`. PowerShell 4103/4104 events reveal the technique's mechanics: `Set-Clipboard -Value 'calc.exe'`, followed by `Start-Process -FilePath "powershell" -ArgumentList "-c (New-Object -ComObject 'Shell.Application').FileRun()" -WindowStyle Hidden`. The COM object instantiation is captured in PowerShell 4103 as `New-Object -ComObject "Shell.Application"`. Sysmon EID 1 events show the process creation chain: initial PowerShell (PID 31852) spawning a child PowerShell (PID 32008) that then creates the COM execution PowerShell (PID 41080) with command line `"-c (New-Object -ComObject 'Shell.Application').FileRun()"`. The dataset includes SendKeys automation evidence in PowerShell logs: `Add-Type -AssemblyName System.Windows.Forms` and `[System.Windows.Forms.SendKeys]::SendWait('^v')` and `SendWait('{ENTER}')`. Sysmon EID 7 events capture .NET Framework DLL loads (mscoreei.dll, clr.dll) and PowerShell automation libraries, while EID 10 shows process access patterns typical of PowerShell process management.

## What This Dataset Does Not Contain

The dataset lacks the final payload execution - notably, there's no calc.exe process creation despite the clipboard containing "calc.exe". This suggests either the GUI automation failed (common in headless environments), Windows Defender blocked the final execution, or the Run dialog didn't properly open. The data contains no registry access events (Sysmon EID 12/13) that would show RunMRU history manipulation, which is a key forensic artifact of this technique. There are no network connections (Sysmon EID 3) or DNS queries (EID 22), indicating this test focused solely on the execution mechanism rather than command-and-control activity. The dataset also lacks any Windows GUI-specific event logs that might capture the actual Run dialog opening or user interface interactions. File creation events are limited to PowerShell profile touches rather than any malicious artifacts.

## Assessment

This dataset provides excellent telemetry for detecting the preparatory phases of RunMRU-based indirect command execution, particularly the PowerShell-driven COM object instantiation and SendKeys automation patterns. The Security 4688 events with full command-line logging are exceptionally valuable, capturing the entire malicious script in the process creation event. PowerShell logging (4103/4104) offers granular visibility into each technique component: clipboard manipulation, COM object creation, and GUI automation setup. Sysmon process creation events (EID 1) provide clear parent-child relationships showing the execution chain. However, the dataset's value is diminished by the apparent failure of the final payload execution, limiting its utility for understanding post-exploitation artifacts. The lack of registry events is particularly notable since RunMRU abuse typically leaves forensic traces in HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU. For comprehensive RunMRU detection, the dataset would be strengthened by successful payload execution and registry monitoring.

## Detection Opportunities Present in This Data

1. **COM Object Instantiation Pattern**: Monitor PowerShell 4103 events for `New-Object -ComObject "Shell.Application"` combined with subsequent `.FileRun()` method calls, particularly when executed with hidden window styles.

2. **Clipboard-to-Execution Chain**: Detect Security 4688 process creation events containing both `Set-Clipboard` operations and `Shell.Application` COM instantiation within the same command line, indicating preparation for GUI automation attacks.

3. **SendKeys GUI Automation**: Alert on PowerShell 4103 events showing `Add-Type -AssemblyName System.Windows.Forms` followed by `SendKeys.SendWait` method calls with control characters (^v, {ENTER}), especially in non-interactive sessions.

4. **Suspicious PowerShell Process Trees**: Monitor Sysmon EID 1 for PowerShell processes spawning child PowerShell instances with COM-related command lines, particularly those using `-WindowStyle Hidden` parameters.

5. **Hidden Window PowerShell Execution**: Flag Security 4688 events for PowerShell processes with command lines containing both COM object instantiation and window style manipulation (`-WindowStyle Hidden`).

6. **Rapid Sleep-SendKeys-Sleep Pattern**: Correlate PowerShell 4103 events showing `Start-Sleep` commands immediately before and after `SendKeys` operations, indicating programmatic timing for GUI automation.
