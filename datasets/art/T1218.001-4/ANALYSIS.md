# T1218.001-4: Compiled HTML File — Invoke CHM with InfoTech Storage Protocol Handler

## Technique Context

T1218.001 leverages Compiled HTML Help (.chm) files to execute arbitrary code while bypassing application controls. CHM files are legitimate Windows help documentation that can contain HTML, JavaScript, and ActiveX controls. The InfoTech Storage Protocol Handler (`its:`) allows direct access to content within CHM files via URLs, enabling attackers to execute embedded scripts or launch processes. This technique is particularly valuable because CHM files are often trusted by security solutions and can be distributed as seemingly benign documentation. Detection teams focus on unusual process chains involving `hh.exe` (HTML Help executable), script execution from CHM contexts, and suspicious network connections or file operations initiated by help processes.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of the Atomic Red Team test that invokes CHM content using the InfoTech Storage Protocol Handler. The primary evidence appears in Security event 4688, showing the creation of a child PowerShell process with the command line `"powershell.exe" & {Invoke-ATHCompiledHelp -InfoTechStorageHandler its -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}`. This command references the standard Windows HTML Help executable (`$env:windir\hh.exe`) and a test CHM file.

PowerShell script block logging captures the technique invocation in event 4104: `& {Invoke-ATHCompiledHelp -InfoTechStorageHandler its -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}`. This shows the function call with the InfoTech Storage Protocol Handler parameter specified as `its`.

Sysmon provides process creation telemetry for both the child PowerShell process (EID 1) and a `whoami.exe` execution, indicating the test successfully spawned additional processes. The Sysmon events show normal PowerShell .NET runtime loading and Windows Defender integration through MpOAV.dll and MpClient.dll, but notably missing any `hh.exe` process creation events.

## What This Dataset Does Not Contain

Critically, this dataset lacks the expected `hh.exe` process creation that would typically occur when invoking CHM files through the InfoTech Storage Protocol Handler. The Sysmon ProcessCreate events (EID 1) show only PowerShell and `whoami.exe` processes, with no evidence of HTML Help executable launch. This suggests either the technique failed to execute the CHM component properly, Windows Defender blocked the `hh.exe` invocation, or the test CHM file was not present/accessible.

The dataset also lacks network connection events (no Sysmon EID 3) that might indicate CHM content attempting to reach external resources, and there are no file access events showing interaction with the referenced `Test.chm` file. DNS queries (Sysmon EID 22) are absent, which would be expected if the CHM contained external references.

## Assessment

This dataset has limited utility for understanding successful T1218.001 execution patterns. While it captures the PowerShell invocation mechanics and function calls, it appears to represent an incomplete or failed test execution rather than successful CHM-based code execution. The absence of `hh.exe` process creation severely limits the dataset's value for building detections around the core technique behavior.

The PowerShell telemetry is valuable for detecting the preparation phase of CHM-based attacks, particularly the `Invoke-ATHCompiledHelp` function signature and InfoTech Storage Protocol Handler references. However, defenders looking to understand the full attack chain and develop comprehensive detections would need additional data showing successful CHM execution.

## Detection Opportunities Present in This Data

1. **PowerShell CHM invocation functions** - Monitor PowerShell script blocks for `Invoke-ATHCompiledHelp` or similar CHM manipulation functions with InfoTech Storage Protocol Handler parameters

2. **InfoTech Storage Protocol Handler references** - Detect PowerShell commands containing `its:` protocol references combined with CHM file paths or HTML Help executable references

3. **Suspicious PowerShell command patterns** - Alert on PowerShell processes spawning with command lines referencing both `hh.exe` and `.chm` files in the same context

4. **Process creation anomalies from PowerShell** - Investigate PowerShell processes that spawn `whoami.exe` or other discovery tools, especially when combined with CHM-related command line parameters

5. **Missing expected process chains** - Develop analytics that flag PowerShell CHM invocation attempts that don't result in corresponding `hh.exe` process creation, potentially indicating blocked or failed attacks
