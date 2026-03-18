# T1218.004-2: InstallUtil — InstallHelper method call

## Technique Context

T1218.004 InstallUtil is a defense evasion technique where attackers abuse Microsoft's InstallUtil.exe utility to execute malicious code. InstallUtil is a legitimate Windows tool that normally installs and uninstalls server resources by executing installer components in assemblies. However, attackers can create malicious installer assemblies that execute arbitrary code when processed by InstallUtil, bypassing application allowlisting and appearing as legitimate software installation activity.

This specific test (T1218.004-2) focuses on the InstallHelper method invocation, which is the core .NET API that InstallUtil.exe wraps. By calling `ManagedInstallerClass.InstallHelper()` directly from PowerShell instead of spawning InstallUtil.exe, this variant avoids creating the typical InstallUtil.exe process that many detections focus on. The detection community particularly values this test because it demonstrates how attackers can achieve the same malicious outcome through different execution paths, requiring more comprehensive detection coverage beyond simple process monitoring.

## What This Dataset Contains

This dataset captures a complete InstallHelper method execution sequence with rich telemetry across multiple data sources:

**PowerShell Script Execution**: PowerShell 4104 events show the test framework script executing: `"powershell.exe" & {# Import the required test framework function, Invoke-BuildAndInvokeInstallUtilAssembly` with InvocationMethod set to 'InstallHelper' and CommandLine parameters `"/logfile= /logtoconsole=false \"$InstallerAssemblyFullPath\""`.

**Assembly Compilation Chain**: Security 4688 events capture the C# compiler chain:
- `"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\xktpcqzx\xktpcqzx.cmdline"`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RESC10A.tmp"`

**File Creation Activity**: Sysmon 11 events document the assembly compilation artifacts including source files (`xktpcqzx.0.cs`), compilation outputs (`T1218.004.dll`), and InstallState tracking (`T1218.004.InstallState`).

**Process Access Monitoring**: Sysmon 10 events show PowerShell accessing the csc.exe processes with GrantedAccess 0x1FFFFF during compilation orchestration.

**CLR Loading Indicators**: Sysmon 7 events capture .NET runtime loading including `mscoree.dll`, `mscoreei.dll`, `clr.dll`, and `System.Management.Automation.ni.dll` in the PowerShell processes.

## What This Dataset Does Not Contain

**No InstallUtil.exe Process**: Since this test uses the InstallHelper method directly, there are no Sysmon ProcessCreate events for InstallUtil.exe - this is the key differentiator from T1218.004-1.

**Limited Assembly Load Monitoring**: While Sysmon captures some .NET framework DLL loads, it doesn't show the malicious assembly itself being loaded through the ManagedInstallerClass.InstallHelper API call.

**No Network Activity**: This test creates a minimal viable assembly that only writes to a file, so there are no network connections or DNS queries that might be present in real-world InstallUtil abuse.

**Missing API Call Details**: The actual `ManagedInstallerClass.InstallHelper()` method invocation occurs within the PowerShell .NET runtime and isn't directly visible in these event sources.

## Assessment

This dataset provides excellent coverage for detecting InstallHelper method abuse, particularly valuable because many organizations focus detection efforts solely on InstallUtil.exe process creation. The compilation chain from PowerShell through csc.exe to assembly creation is clearly documented across Security and Sysmon channels. The PowerShell script block logging captures the full attack technique implementation, including the specific API usage pattern.

The file creation events for the compiled assembly and InstallState file provide additional detection opportunities beyond process monitoring. However, detection engineers should note that the core malicious activity (the InstallHelper method call and assembly execution) happens within the PowerShell CLR runtime without generating additional process creation events.

## Detection Opportunities Present in This Data

1. **PowerShell ManagedInstallerClass Usage**: Monitor PowerShell script block logs (4104) for references to `ManagedInstallerClass.InstallHelper` or `System.Configuration.Install` namespaces.

2. **Assembly Compilation from PowerShell**: Detect PowerShell processes spawning csc.exe with command lines referencing temporary directories and assembly compilation parameters.

3. **InstallState File Creation**: Monitor for file creation events with `.InstallState` extensions in temporary directories, which indicate installer assembly tracking.

4. **Suspicious Assembly Compilation Patterns**: Alert on csc.exe processes with parent PowerShell processes, particularly when source files are created in SystemTemp directories.

5. **PowerShell Add-Type with Installer References**: Look for PowerShell Add-Type operations that reference `System.Configuration.Install` assemblies combined with OutputAssembly parameters.

6. **Rapid File Creation in Temp Directories**: Correlate multiple file creations in the same temporary directory (source, cmdline, output files) within short time windows.

7. **CLR Assembly Loading Anomalies**: Monitor for unusual System.Configuration.Install assembly loading patterns in PowerShell processes that don't correspond to legitimate software installation.
