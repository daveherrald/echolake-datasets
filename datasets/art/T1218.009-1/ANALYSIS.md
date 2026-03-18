# T1218.009-1: Regsvcs/Regasm — Regasm Uninstall Method Call Test

## Technique Context

T1218.009 (Regsvcs/Regasm) is a defense evasion technique where adversaries abuse Microsoft's legitimate .NET assembly registration utilities (regsvcs.exe and regasm.exe) to proxy execution of arbitrary code. These utilities are designed to register and unregister .NET assemblies for COM interop, but they can be misused to execute malicious code within the context of a trusted Microsoft-signed binary.

The technique is valuable to attackers because it bypasses application whitelisting solutions that trust signed Microsoft binaries, provides a living-off-the-land approach using pre-installed Windows utilities, and can execute code with the privileges of the regasm/regsvcs process. Detection engineering typically focuses on monitoring process creation events for these utilities, especially when they load unsigned assemblies or are invoked from unusual parent processes.

The MITRE ATT&CK community emphasizes detecting unusual command-line arguments (particularly /U for uninstall operations), monitoring for assembly loading events, and correlating regasm/regsvcs execution with suspicious file creation patterns.

## What This Dataset Contains

This dataset captures the complete execution chain of the Atomic Red Team T1218.009-1 test, which demonstrates regasm.exe being used to execute code through an "uninstall" operation:

**Process Chain:** The execution begins with PowerShell (PID 32728) launching cmd.exe with the command: `"cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"%tmp%\T1218.009.dll" /target:library "C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs" & C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U %tmp%\T1218.009.dll`

**Compilation Phase:** Security event 4688 shows csc.exe (PID 35888) compiling the malicious C# source into a DLL: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"C:\Windows\TEMP\T1218.009.dll" /target:library "C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs"`

**Target Execution:** Sysmon EID 1 captures regasm.exe (PID 22712) being created with the uninstall flag: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U C:\Windows\TEMP\T1218.009.dll`

**DLL Loading Evidence:** Critical Sysmon EID 7 events show regasm.exe loading the malicious assembly four times: `C:\Windows\Temp\T1218.009.dll` with hash SHA256=F7A1EFE3A9DBB8C85926C494CED6651C4FB4F6D70F03986C2C9CF73A65630784

**File Operations:** Sysmon EID 11 events document the creation of the compiled DLL at `C:\Windows\Temp\T1218.009.dll` and temporary compilation artifacts.

## What This Dataset Does Not Contain

The dataset shows a successful technique execution with no blocking by Windows Defender, evidenced by clean exit codes (0x0) in Security event 4689 for all processes. This means we don't see any STATUS_ACCESS_DENIED (0xC0000022) events that would indicate endpoint protection interference.

The dataset lacks network-related events - there are no Sysmon EID 3 (network connections) or EID 22 (DNS queries) events, suggesting this test doesn't include command-and-control communications or payload downloading components.

Missing are detailed registry modification events that might occur during the actual assembly registration/unregistration process, likely due to the sysmon-modular configuration focusing on process and file events rather than comprehensive registry monitoring.

The PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual technique implementation, as the test uses cmd.exe and compiled binaries rather than PowerShell scripts.

## Assessment

This dataset provides excellent coverage for T1218.009 detection development. The Security 4688 events with full command-line auditing capture the complete attack chain including the compilation and execution phases. Sysmon's process creation, image load, and file creation events provide comprehensive telemetry for both behavioral and artifact-based detection approaches.

The multiple Sysmon EID 7 events showing the same unsigned DLL being loaded repeatedly by regasm.exe are particularly valuable for detection engineering, as this loading pattern is highly indicative of the technique. The combination of process creation events showing regasm.exe with the /U flag and subsequent loading of unsigned assemblies provides strong detection signals.

The dataset would be stronger with registry events showing the actual COM registration activities and network events if the payload included callback functionality, but the current coverage effectively supports detection of the core technique execution.

## Detection Opportunities Present in This Data

1. **RegAsm Process Creation with Uninstall Flag** - Security 4688 events showing regasm.exe spawning with `/U` parameter, especially from unusual parent processes like cmd.exe or PowerShell

2. **Unsigned Assembly Loading by RegAsm** - Sysmon EID 7 events where regasm.exe loads unsigned DLLs (Signed: false, SignatureStatus: Unavailable) from temporary directories

3. **Dynamic DLL Compilation and Execution Pattern** - Sequential events showing csc.exe compilation followed by regasm.exe execution within short timeframes

4. **Temporary Directory Assembly Creation** - Sysmon EID 11 file creation events for .dll files in %temp% or temporary directories followed by regasm.exe execution

5. **Suspicious Parent-Child Process Relationships** - Process chains where cmd.exe or PowerShell spawn both csc.exe and regasm.exe in sequence

6. **Multiple Assembly Loading Events** - Repeated Sysmon EID 7 events showing the same assembly being loaded multiple times by regasm.exe (indicating execution of uninstall methods)

7. **Compilation Command Line Indicators** - Security 4688 events showing csc.exe with `/target:library` and references to System.EnterpriseServices.dll
