# T1218.004-1: InstallUtil — CheckIfInstallable method call

## Technique Context

T1218.004 represents the use of InstallUtil.exe, a legitimate Microsoft signed binary, to proxy execution of malicious code. InstallUtil is designed to install and uninstall server resources by executing installer components in .NET assemblies. Attackers abuse this functionality by creating malicious assemblies with code in their constructors or installer methods, then using InstallUtil to execute them.

This particular test focuses on the CheckIfInstallable method, which is one of several ways to execute code through InstallUtil without actually running the full installer process. The CheckIfInstallable method executes the constructor of an installer assembly, making it a stealthier variant compared to direct InstallUtil.exe execution. Detection engineers focus on monitoring .NET compilation activity, assembly creation in temp directories, and the loading of suspicious assemblies through .NET APIs.

## What This Dataset Contains

The dataset captures a complete execution chain for the CheckIfInstallable method variant of T1218.004. The PowerShell script block logs (EID 4104) show the full test framework code that creates and compiles a malicious installer assembly with `InvocationMethod = 'CheckIfInstallable'`.

Security EID 4688 events show the process creation chain: PowerShell spawns csc.exe (`"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\rwazgsp2\rwazgsp2.cmdline"`) which then spawns cvtres.exe for resource compilation. 

Sysmon EID 1 events capture the same process creations with Sysmon's enhanced telemetry, including the csc.exe execution (ProcessId 33064) tagged with `technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution`.

Sysmon EID 11 file creation events show the compilation artifacts: temporary files in `C:\Windows\SystemTemp\rwazgsp2\` including the source file `rwazgsp2.0.cs`, and the final compiled assembly `C:\Windows\Temp\T1218.004.dll`.

The technique executes entirely through .NET APIs rather than spawning InstallUtil.exe, as evidenced by the PowerShell code calling `[Configuration.Install.AssemblyInstaller]::CheckIfInstallable($OutputAssemblyFullPath)` directly.

## What This Dataset Does Not Contain

This dataset does not contain direct InstallUtil.exe process creation since the CheckIfInstallable method is invoked through .NET APIs within the PowerShell process rather than as a separate executable. There are no Sysmon ProcessCreate events for InstallUtil.exe itself.

The dataset lacks network activity or file system persistence beyond the temporary compilation artifacts, as this is a minimal test focused solely on code execution validation. There are no registry modifications or service installations that might occur in more sophisticated InstallUtil abuse scenarios.

Windows Defender real-time protection was active but did not block this technique, allowing it to complete successfully. The technique generated normal .NET compilation telemetry rather than triggering defensive responses.

## Assessment

This dataset provides excellent telemetry for detecting the CheckIfInstallable variant of InstallUtil abuse. The combination of PowerShell script block logging capturing the malicious test framework code, Security audit logs showing csc.exe compilation, and Sysmon file creation events tracking assembly artifacts creates multiple detection opportunities.

The data quality is particularly strong for behavioral detection, as the .NET compilation process and temporary file patterns are highly distinctive. However, the dataset would be strengthened by including examples of the technique executing with different assembly names, locations, or compiler flags to test detection robustness.

## Detection Opportunities Present in This Data

1. Monitor PowerShell script blocks containing `CheckIfInstallable` method calls combined with `Add-Type` compilation activities
2. Detect csc.exe spawned from PowerShell with command-line arguments referencing temporary directories in SystemTemp
3. Alert on file creation of .dll files in Windows temp directories following csc.exe compilation activity
4. Track PowerShell processes loading .NET installer-related assemblies (`System.Configuration.Install`) outside of legitimate installer contexts
5. Correlate temporary file creation in SystemTemp with .cs source files and subsequent .dll compilation within short time windows
6. Monitor for PowerShell accessing installer assembly functionality without corresponding InstallUtil.exe process creation
7. Detect compilation artifacts (cmdline files, temporary source files) created in Windows system temporary directories by development tools
