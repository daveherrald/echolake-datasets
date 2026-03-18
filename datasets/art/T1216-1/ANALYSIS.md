# T1216-1: System Script Proxy Execution — SyncAppvPublishingServer Signed Script PowerShell Command Execution

## Technique Context

T1216 System Script Proxy Execution involves adversaries leveraging legitimate system scripts to execute malicious commands while evading detection. The specific test here exploits `SyncAppvPublishingServer.vbs`, a Microsoft-signed VBScript that can execute PowerShell commands passed as parameters. This technique is particularly valuable for defense evasion because it uses a legitimate, trusted system binary to proxy malicious execution, potentially bypassing application whitelisting and security controls that focus on unsigned or suspicious binaries.

The detection community focuses on monitoring for unusual command-line patterns with system proxy scripts, especially when they invoke PowerShell or contain suspicious parameters. The challenge lies in distinguishing legitimate administrative use from malicious abuse of these trusted system utilities.

## What This Dataset Contains

This dataset captures a complete execution chain demonstrating the SyncAppvPublishingServer proxy technique. The Security 4688 events show the full process chain: an initial PowerShell process (PID 35148) executes `Sync-AppvPublishingServer` cmdlet, which spawns `cmd.exe` with the command line `"cmd.exe" /c C:\windows\system32\SyncAppvPublishingServer.vbs "\n;Start-Process calc"`. This cmd.exe then launches `wscript.exe` with the full command `"C:\Windows\System32\WScript.exe" "C:\windows\system32\SyncAppvPublishingServer.vbs" "\n;Start-Process calc"`.

The wscript.exe process (PID 31900) loads key DLLs including `amsi.dll`, `vbscript.dll`, and `wshom.ocx`, indicating VBScript execution capabilities. This spawns a final PowerShell process (PID 36684) with the decoded command `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -Command &{$env:psmodulepath = [IO.Directory]::GetCurrentDirectory(); import-module AppvClient; Sync-AppvPublishingServer \n;Start-Process calc}`.

PowerShell event 4103 shows the actual cmdlet invocations, including a failed `Import-Module AppvClient` attempt and successful execution of `Sync-AppvPublishingServer` and `Start-Process calc`. The technique successfully launches calc.exe (PID 9352) as the payload.

Sysmon ProcessCreate events capture the process chain with rule tags identifying techniques: T1033 (System Owner/User Discovery) for whoami.exe, T1059.003 (Windows Command Shell) for cmd.exe, T1202 (Indirect Command Execution) for wscript.exe, and T1083 (File and Directory Discovery) for the final PowerShell process.

## What This Dataset Does Not Contain

The dataset lacks Sysmon ProcessCreate events for the initial PowerShell processes due to the sysmon-modular configuration's include-mode filtering, which only captures processes matching known suspicious patterns. While the technique executed successfully, there are no network connections or file system artifacts beyond PowerShell profile data creation. The AppvClient module import fails as expected since App-V isn't installed, but this doesn't prevent the technique from working.

There are no Windows Defender blocks or quarantine events despite real-time protection being active, indicating this technique successfully evaded endpoint protection at the time of execution.

## Assessment

This dataset provides excellent coverage for detecting the SyncAppvPublishingServer proxy technique. The Security 4688 events with command-line logging capture the complete attack chain, while PowerShell operational logs reveal the actual malicious commands executed. Sysmon adds valuable context with process access events, DLL loads, and technique-specific rule tagging.

The combination of Security and PowerShell logs would be sufficient for detection, but Sysmon enriches the data significantly. The clear command-line evidence and process relationships make this an ideal dataset for developing robust detection rules for this specific proxy execution technique.

## Detection Opportunities Present in This Data

1. **SyncAppvPublishingServer Command Line Anomalies**: Monitor Security 4688 events for wscript.exe executing SyncAppvPublishingServer.vbs with unusual parameters, especially those containing PowerShell commands or suspicious character sequences like newlines.

2. **PowerShell Execution via System Script Proxy**: Detect PowerShell processes spawned by wscript.exe where the parent command line contains SyncAppvPublishingServer.vbs and suspicious PowerShell parameters.

3. **Sync-AppvPublishingServer Cmdlet with Suspicious Parameters**: Alert on PowerShell 4103 events showing Sync-AppvPublishingServer cmdlet execution with non-standard Name parameter values, particularly those containing command separators or executable names.

4. **Process Chain Analysis**: Build detections for the specific process chain: PowerShell → cmd.exe → wscript.exe → PowerShell where intermediate processes reference SyncAppvPublishingServer.vbs.

5. **VBScript Execution with PowerShell Payload**: Monitor for wscript.exe processes loading amsi.dll and vbscript.dll when the command line contains PowerShell execution parameters.

6. **Hidden PowerShell with ExecutionPolicy Bypass**: Detect PowerShell processes with -NonInteractive, -WindowStyle Hidden, and -ExecutionPolicy RemoteSigned parameters, especially when the parent is wscript.exe.

7. **Failed Module Import Correlation**: Correlate failed AppvClient module imports in PowerShell logs with subsequent Sync-AppvPublishingServer cmdlet execution as an indicator of proxy technique attempts.
