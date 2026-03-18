# T1218.005-4: Mshta — Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement

## Technique Context

T1218.005 represents the abuse of Microsoft HTML Application Host (mshta.exe) to execute malicious code while bypassing application controls. Mshta.exe is a signed Microsoft binary that can execute HTML Applications (.hta files) containing embedded scripting languages like VBScript or JScript. Attackers leverage this technique because mshta.exe is a trusted binary that can execute arbitrary code from local files, remote URLs, or UNC paths, making it an effective defense evasion method.

This specific test simulates lateral movement by using mshta.exe to execute JScript from a local UNC path, mimicking how attackers might distribute malicious HTA files across network shares during post-exploitation phases. The detection community focuses on monitoring mshta.exe process creation, command-line arguments containing script engines or UNC paths, network connections to suspicious locations, and the execution of child processes spawned by mshta.exe.

## What This Dataset Contains

The dataset captures a PowerShell-based execution of the Atomic Red Team test that attempts to invoke an HTML Application using JScript engine over a local UNC path. The key telemetry includes:

**PowerShell Script Block Logging (EID 4104):** Contains the actual test execution command `Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath $env:windir\system32\mshta.exe`

**Security Process Creation Events (EID 4688):** Show the PowerShell process chain with the full command line `"powershell.exe" & {Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath $env:windir\system32\mshta.exe}`

**Sysmon Process Creation (EID 1):** Captures two processes - `whoami.exe` with command line `"C:\Windows\system32\whoami.exe"` and a child PowerShell process with the full Invoke-ATHHTMLApplication command line

**Process Access Events (EID 10):** Shows PowerShell accessing both the whoami.exe process and another PowerShell process with full access rights (0x1FFFFF)

## What This Dataset Does Not Contain

Notably absent is any mshta.exe process creation, which indicates the technique was likely blocked by Windows Defender before the mshta.exe binary could be executed. The test appears to have executed the PowerShell wrapper and setup components but did not successfully launch the actual mshta.exe process that would demonstrate the T1218.005 technique.

Missing telemetry includes:
- No mshta.exe process creation events
- No .hta file creation or access
- No network connections to UNC paths
- No HTML/JScript execution artifacts
- No file system artifacts from the simulated lateral movement

The absence of these events suggests Windows Defender's real-time protection prevented the core technique execution while still allowing the test framework PowerShell commands to run.

## Assessment

This dataset has limited utility for building detections specific to T1218.005 since the actual mshta.exe execution was blocked. However, it provides valuable telemetry for detecting the setup and preparation phases of mshta.exe abuse attempts. The PowerShell script block logging captured the complete attack command line, which is valuable for detecting similar tooling or frameworks that attempt to invoke mshta.exe programmatically.

The dataset is most useful for understanding how security tools can capture intent and preparation for living-off-the-land binary abuse even when the execution is blocked. The combination of Security 4688 and PowerShell 4104 events provides complementary coverage for command-line based detection.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor PowerShell EID 4104 events for references to "mshta", "HTAFilePath", "ScriptEngine", and "UNC" parameters that indicate mshta abuse preparation

2. **Command Line Pattern Detection** - Alert on Security EID 4688 events containing PowerShell command lines with "Invoke-ATHHTMLApplication" or similar function names combined with mshta.exe references

3. **Suspicious PowerShell Parameter Combinations** - Flag PowerShell executions containing combinations of "JScript", "AsLocalUNCPath", and "SimulateLateralMovement" parameters

4. **Process Relationship Analysis** - Monitor for PowerShell processes that attempt to access other processes with full permissions (0x1FFFFF) shortly after mshta-related command execution

5. **Atomic Red Team Framework Detection** - Identify PowerShell script blocks containing "Invoke-ATH" function patterns which may indicate red team testing or adversary use of similar frameworks
