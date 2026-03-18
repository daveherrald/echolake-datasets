# T1220-1: XSL Script Processing — MSXSL Bypass using local files

## Technique Context

T1220 XSL Script Processing is a defense evasion technique where attackers abuse XSLT (Extensible Stylesheet Language Transformations) processors to execute arbitrary code. The most common implementation uses Microsoft's MSXSL.exe command-line utility, which can process XML files with XSL stylesheets that contain embedded scripting code. This technique is particularly attractive to attackers because MSXSL.exe is a signed Microsoft binary that can execute JScript or VBScript code embedded in XSL files, potentially bypassing application whitelisting controls. The detection community focuses on monitoring for MSXSL.exe execution, command-line arguments referencing XML/XSL files, and the creation of child processes from MSXSL that indicate successful code execution.

## What This Dataset Contains

This dataset captures a failed attempt to execute T1220 using MSXSL.exe with local XML and XSL files. The key evidence includes:

**Process Creation Chain (Security 4688/Sysmon 1):** PowerShell (PID 7624) spawned cmd.exe (PID 12932) with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\msxsl.exe" "C:\AtomicRedTeam\atomics\T1220\src\msxslxmlfile.xml" "C:\AtomicRedTeam\atomics\T1220\src\msxslscript.xsl"`. The cmd.exe process exited with status 0x1, indicating failure.

**MSXSL.exe Execution Evidence:** The command line clearly shows an attempt to invoke MSXSL.exe with two file arguments - an XML input file and an XSL stylesheet file, which is the standard pattern for T1220 execution.

**Process Access Events (Sysmon 10):** Two process access events show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating normal parent-child process relationships during test execution.

**PowerShell Activity:** The PowerShell channel contains only test framework boilerplate - Set-ExecutionPolicy bypass commands and error handling scriptblocks. No actual attack script content is present.

## What This Dataset Does Not Contain

**MSXSL.exe Process Creation:** Critically, there are no Sysmon ProcessCreate (EID 1) or Security process creation (EID 4688) events for MSXSL.exe itself. The sysmon-modular config's include-mode filtering doesn't capture MSXSL.exe by default, and the absence of Security 4688 events for MSXSL suggests it was never successfully launched.

**Code Execution Evidence:** No child processes, file writes, network connections, or other artifacts indicating successful XSL script execution are present. The cmd.exe exit status of 0x1 confirms the MSXSL execution failed.

**XSL File Content:** The dataset doesn't contain the actual XSL stylesheet content that would show the embedded scripting code, though the file paths indicate standard Atomic Red Team test files were used.

**Error Details:** No events capture why MSXSL.exe failed to execute - whether due to missing files, Windows Defender blocking, or other environmental factors.

## Assessment

This dataset provides limited utility for T1220 detection engineering because it captures only a failed attempt. The most valuable elements are the command-line patterns showing MSXSL.exe invocation with XML/XSL file arguments, which demonstrate the initial execution vector. However, the lack of actual MSXSL.exe process creation and execution artifacts significantly reduces its value for understanding the full attack chain and developing comprehensive detections. The dataset is most useful for detecting attempted T1220 execution based on command-line analysis, but provides no insight into successful exploitation patterns or post-execution behaviors.

## Detection Opportunities Present in This Data

1. **MSXSL.exe Command Line Detection** - Monitor Security 4688 events for cmd.exe or PowerShell command lines containing "msxsl.exe" with XML and XSL file arguments, indicating T1220 attempt

2. **Suspicious File Extension Patterns** - Detect command lines referencing both .xml and .xsl files in the same execution context, particularly when invoked via cmd.exe or PowerShell

3. **Atomic Red Team Test Path Detection** - Alert on command lines containing "AtomicRedTeam" and "ExternalPayloads" paths combined with MSXSL.exe, indicating security testing activity

4. **Process Chain Analysis** - Monitor for PowerShell spawning cmd.exe with MSXSL-related command lines as an execution pattern for T1220

5. **Failed Execution Monitoring** - Track cmd.exe processes with exit code 0x1 when command lines contain MSXSL.exe to identify failed attack attempts or environmental issues blocking execution
