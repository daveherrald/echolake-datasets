# T1202-5: Indirect Command Execution — RunMRU Dialog

## Technique Context

T1202 (Indirect Command Execution) includes techniques where legitimate Windows GUI components are used to execute commands in a way that obscures the true originator. This variant abuses the Windows Run dialog (Win+R) programmatically through PowerShell's `Shell.Application` COM object and keyboard automation (`SendKeys`). The attack flow is: place a command on the clipboard, programmatically open the Run dialog via `Shell.Application.FileRun()`, then simulate Ctrl+V to paste and Enter to execute. The resulting process appears to have been launched by `explorer.exe` or the shell subsystem rather than the attacking PowerShell process, because the Run dialog is handled by the shell's own process context.

This is particularly evasive in environments where process lineage is the primary detection mechanism, since the executed command traces back to `explorer.exe` in the process tree rather than to the attacker's PowerShell session.

## What This Dataset Contains

This dataset captures the PowerShell-based Run dialog automation chain. Security EID 4688 records 5 process creations, including multiple PowerShell instances involved in the multi-step execution. Sysmon EID 1 captures two key creations: an initial `whoami.exe` (test framework validation), and a PowerShell process tagged with `RuleName: technique_id=T1027,technique_name=Obfuscated Files or Information` (PID 18124), which is the PowerShell process executing the COM-based clipboard and Run dialog automation.

The defended dataset analysis (Sysmon: 56, Security: 13, PowerShell: 57) includes PowerShell 4103/4104 blocks revealing the specific automation code: `Set-Clipboard -Value 'calc.exe'`, `Start-Process -FilePath "powershell" -ArgumentList "-c (New-Object -ComObject 'Shell.Application').FileRun()" -WindowStyle Hidden`, `Add-Type -AssemblyName System.Windows.Forms`, `[System.Windows.Forms.SendKeys]::SendWait('^v')`, and `[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')`.

This undefended dataset captures 51 Sysmon events (34 EID 7 DLL loads, 5 EID 1, 4 EID 17, 4 EID 10, 4 EID 11) and 5 Security EID 4688 events. The 4 EID 11 file creation events include PowerShell startup profile writes and additional profile files indicating multiple PowerShell processes initializing, consistent with the technique's use of `Start-Process` to spawn additional PowerShell instances for the COM automation.

The PowerShell channel records 130 events (121 EID 4104, 9 EID 4103). The larger script block count relative to the defended variant (57 events) reflects the full test framework execution completing without AMSI truncation. The 4103 module invocation events include `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"` confirmations.

## What This Dataset Does Not Contain

The final payload execution — `calc.exe` appearing as a child of `explorer.exe` — is not captured in the available samples. In a headless QEMU guest agent execution environment, the Windows Run dialog may not open or render correctly, causing the SendKeys automation to fail without generating an error. This is an inherent limitation of testing GUI automation techniques in automated environments. The technique's core artifacts (the COM object instantiation, clipboard manipulation, SendKeys calls) remain detectible through PowerShell script block logging even when the final execution fails.

No Sysmon EID 12/13 (registry access/modification) events are present, which would normally show the RunMRU registry key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) being updated when the Run dialog is used — another forensic artifact that would exist in an interactive user session.

## Assessment

The undefended dataset shows moderately more telemetry than the defended one (51 vs. 56 Sysmon events — the defended version is actually larger due to more process creation events when Defender scans are active). The most important difference is in the PowerShell channel: 130 events vs. 57 in the defended run, with the undefended run capturing more of the automation script blocks.

The technique's detection relies heavily on PowerShell script block logging because the process lineage evidence is intentionally designed to be weak. The combination of `Shell.Application` COM instantiation, `Set-Clipboard` with a command string, and `SendKeys` automation in the same script block is a distinctive behavioral cluster that does not appear in legitimate automation. Detection programs should focus on this behavioral pattern rather than process ancestry alone.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Script blocks containing `New-Object -ComObject "Shell.Application"` combined with `.FileRun()` method call indicate programmatic Run dialog access
- **PowerShell EID 4104**: `Set-Clipboard -Value` followed by `SendKeys` automation (`SendWait('^v')` paste + `SendWait('{ENTER}')` execute) is a highly specific pattern for keyboard injection attacks against GUI dialogs
- **PowerShell EID 4104**: `Add-Type -AssemblyName System.Windows.Forms` combined with SendKeys usage signals UI automation being weaponized for command execution
- **PowerShell EID 4103**: `Start-Process` invocations creating hidden-window (`-WindowStyle Hidden`) child PowerShell processes in a chain indicate deliberate process splitting to obscure the attack chain
- **Sysmon EID 1**: PowerShell processes tagged with `technique_id=T1027` (Obfuscated Files or Information) by sysmon-modular rule sets, triggered by the obfuscated command structure
- **Registry forensics (not in this dataset)**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` would contain the injected command string in a live system — this key is a valuable post-compromise artifact
