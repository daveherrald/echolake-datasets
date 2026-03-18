# T1218-6: System Binary Proxy Execution — Renamed Microsoft.Workflow.Compiler.exe Payload Executions

## Technique Context

T1218.006 focuses on abusing Microsoft.Workflow.Compiler.exe (Microsoft.NET Framework Workflow Compiler) as a signed binary proxy to execute arbitrary .NET assemblies. Attackers leverage this technique to bypass application whitelisting controls since the binary is legitimately signed by Microsoft and typically trusted by security solutions. The technique involves providing a malicious XML workflow file that references arbitrary .NET code, effectively turning the workflow compiler into a code execution mechanism.

Detection engineers primarily focus on monitoring for suspicious executions of Microsoft.Workflow.Compiler.exe, particularly when invoked with unusual command-line arguments, executed from unexpected locations, or accessing non-standard XML files. The technique is particularly concerning because it can execute managed code while appearing as a legitimate Microsoft process.

## What This Dataset Contains

This dataset demonstrates an attempt to execute the technique using a renamed copy of Microsoft.Workflow.Compiler.exe. The core attack sequence is captured in the PowerShell script block and Security 4688 events:

The malicious command line from Security EID 4688: `"powershell.exe" & {&\"C:\AtomicRedTeam\atomics\..\ExternalPayloads\svchost.exe\" \"C:\AtomicRedTeam\atomics\T1218\src\T1218.xml\" output.txt}`

The PowerShell script block (EID 4104) shows: `& {&"C:\AtomicRedTeam\atomics\..\ExternalPayloads\svchost.exe" "C:\AtomicRedTeam\atomics\T1218\src\T1218.xml" output.txt}`

The technique attempts to use a renamed Microsoft.Workflow.Compiler.exe (`svchost.exe`) located at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\svchost.exe` to process a malicious workflow XML file at `C:\AtomicRedTeam\atomics\T1218\src\T1218.xml`.

Security events capture the PowerShell process creation (PID 7916) with the full command line, and Sysmon EID 1 events show both the PowerShell invocation and the creation of a `whoami.exe` process (PID 32608) that appears to be triggered as part of the workflow execution.

## What This Dataset Does Not Contain

Critically, this dataset lacks a Sysmon ProcessCreate event for the renamed Microsoft.Workflow.Compiler.exe execution itself. The sysmon-modular configuration uses include-mode filtering for ProcessCreate events, capturing only processes matching known-suspicious patterns. Since the binary is renamed to `svchost.exe` and may not match the filtering rules for Microsoft.Workflow.Compiler.exe abuse, this execution was not captured in Sysmon EID 1 events.

The dataset also doesn't contain file creation events for the output file (`output.txt`), network connections that might result from payload execution, or any error events that would indicate whether the workflow compilation succeeded or failed. There are no Application or System log events that might show Microsoft.Workflow.Compiler.exe errors or warnings.

## Assessment

This dataset provides moderate utility for detection engineering, primarily demonstrating the challenge of detecting renamed binary abuse. The PowerShell script block logging (EID 4104) and Security command-line logging (EID 4688) capture the attack attempt with full fidelity, including the renamed binary path and XML file arguments. However, the lack of process creation events for the actual malicious binary execution significantly limits visibility into the technique's success.

The presence of `whoami.exe` execution suggests the workflow may have partially succeeded, but without process creation events for the renamed compiler, we cannot definitively trace the execution chain. This highlights a critical gap where process filtering configurations may miss renamed legitimate binaries used maliciously.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: PowerShell script blocks and command lines containing paths to renamed executables with XML file arguments, particularly when the executable name doesn't match expected Microsoft binaries.

2. **Suspicious PowerShell Execution Patterns**: Commands invoking executables from AtomicRedTeam or similar testing framework paths with XML files as arguments.

3. **Process Parent-Child Relationships**: PowerShell spawning `whoami.exe` without an intermediate process visible in logs, suggesting a missing execution step that should be investigated.

4. **File Path Anomalies**: References to legitimate Microsoft tools (like workflow compiler functionality) executed from non-standard locations like `ExternalPayloads` directories.

5. **Command Line Parameter Analysis**: Executables with names like `svchost.exe` being invoked with XML file arguments, which is inconsistent with legitimate svchost.exe behavior.

6. **PowerShell Script Block Patterns**: Script blocks containing execution of binaries with XML workflow files, particularly when combined with output redirection to text files.
