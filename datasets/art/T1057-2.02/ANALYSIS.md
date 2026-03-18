# T1057-2: Process Discovery — Process Discovery via tasklist

## Technique Context

T1057 Process Discovery is a reconnaissance technique where adversaries enumerate running processes to understand the target environment. The information gained — process names, PIDs, associated services, memory usage — helps attackers identify security tools to evade, locate specific targets for injection or credential dumping, confirm that malware is still running, or determine privilege levels. `tasklist.exe` is one of the oldest and most commonly used Windows utilities for this purpose, available in every Windows version and requiring no special privileges to run in its default mode.

While `tasklist` is a legitimate administrative tool, its execution in suspicious contexts is a reliable indicator of reconnaissance activity. Adversaries routinely run it early in a compromise to take a process snapshot, often piping output to a file or exfiltrating it via the C2 channel. Detection teams focus on the execution context: who launched `tasklist`, from what parent process, under what account, and at what time. A `tasklist` invocation spawned by a PowerShell script running as `NT AUTHORITY\SYSTEM` is categorically different from an administrator running it interactively.

This dataset provides the undefended baseline for this technique. Since `tasklist` is not malicious software, Windows Defender does not block it regardless of defense state — the undefended and defended datasets for this test are comparable in event counts (18 sysmon events here vs. 20 defended), confirming that the difference is environmental noise rather than Defender intervention.

## What This Dataset Contains

The dataset spans three seconds (2026-03-14T23:17:04Z to 23:17:07Z) and records 128 events across four channels: Sysmon (18), PowerShell (104), Security (5), and Application (1).

**The full execution chain is visible across Security and Sysmon.** Security EID 4688 records five process creation events:

- `"C:\Windows\system32\whoami.exe"` — the test framework's pre-test identity confirmation
- `"cmd.exe" /c tasklist` — PowerShell spawning cmd.exe to run tasklist
- `tasklist` — cmd.exe spawning tasklist.exe itself
- `"C:\Windows\system32\whoami.exe"` — post-test identity confirmation
- `"cmd.exe" /c` — the cleanup step

Sysmon EID 1 adds richer context for the same events. The `tasklist.exe` process creation record shows:

- `Image: C:\Windows\System32\tasklist.exe`
- `CommandLine: tasklist`
- `ParentImage: C:\Windows\System32\cmd.exe`
- `ParentCommandLine: "cmd.exe" /c tasklist`
- `User: NT AUTHORITY\SYSTEM`
- `RuleName: technique_id=T1057,technique_name=Process Discovery`

The Sysmon rule tag confirms that the sysmon-modular configuration correctly identifies `tasklist.exe` as a process discovery tool. The `cmd.exe` process creation event is tagged `technique_id=T1059.003,technique_name=Windows Command Shell`, reflecting the PowerShell → cmd.exe execution pattern.

**Sysmon EID 10 (ProcessAccess)** shows two events. The first targets `whoami.exe` with `GrantedAccess: 0x1FFFFF` (tagged as T1055.001) and the second targets `cmd.exe` with the same access level. The call traces pass through CLR assembly code — this is the PowerShell test framework making process access calls as part of its child process management, not a malicious injection attempt. This is expected behavioral noise from the ART test framework.

**Sysmon EID 7 (ImageLoad)** contributes 7 events showing `clrjit.dll`, `MpOAV.dll`, `MpClient.dll`, and `urlmon.dll` loading into the test framework `powershell.exe`. This is the same pattern of .NET/Defender DLL loads seen across all ART tests.

**Sysmon EID 17 (PipeCreate)** shows the test framework PowerShell named pipe: `\PSHost.134180038219626344.3252.DefaultAppDomain.powershell`.

**PowerShell EID 4104** contributes 102 script block events plus 2 EID 4103 (module logging) events. The samples show framework boilerplate. The EID 4103 events are notable because they include module invocation logging — these appear when PowerShell cmdlets are called with parameters, providing additional telemetry about what the script actually executed beyond just the script block text.

The Application channel has one event (EID 15, Defender status update).

## What This Dataset Does Not Contain

The dataset does not include the actual output of `tasklist` — what processes were running at the time of enumeration. This is inherent to the telemetry model; process creation events record that the tool ran, not what it returned.

No Network or file write events capture the output being exfiltrated or saved. In a real attack scenario, the `tasklist` output would typically be written to a file or piped to a network exfiltration channel — this dataset only exercises the local execution variant.

The PowerShell EID 4104 samples do not include the script block fragment containing the `tasklist` invocation command itself, though this is a sampling artifact.

## Assessment

This is a clean, high-fidelity dataset for the basic `tasklist` process discovery pattern. The execution chain from PowerShell → cmd.exe → tasklist.exe is fully documented across both Security and Sysmon channels with consistent field values. Sysmon's automatic rule tagging (`technique_id=T1057`) fires correctly, confirming the sysmon-modular configuration covers this technique. The dataset is appropriate for validating detection rules, building training data for behavioral models, and establishing baselines for what a scripted `tasklist` invocation looks like vs. interactive use.

The minimal difference from the defended version (18 vs. 20 events) confirms this test is unaffected by Defender state, making the dataset representative of what you would see in any Windows environment with comparable Sysmon coverage.

## Detection Opportunities Present in This Data

1. **tasklist.exe spawned by cmd.exe which was spawned by PowerShell**: The three-process chain `powershell.exe → cmd.exe /c tasklist → tasklist.exe` is captured in both Security EID 4688 and Sysmon EID 1. This specific grandparent-parent-child relationship is anomalous for interactive use and worth detecting when the grandparent is a script interpreter.

2. **tasklist.exe with NT AUTHORITY\SYSTEM context**: Sysmon EID 1 shows `User: NT AUTHORITY\SYSTEM`. Administrative tools running discovery commands under SYSTEM are worth flagging, particularly outside of known maintenance windows.

3. **Sysmon RuleName=T1057 on tasklist.exe**: The sysmon-modular configuration fires `technique_id=T1057,technique_name=Process Discovery` on `tasklist.exe` creation. If your SIEM receives Sysmon events, this rule tag is a ready-made alert trigger.

4. **cmd.exe with /c flag spawned by PowerShell**: Security EID 4688 shows `"cmd.exe" /c tasklist` spawned by `powershell.exe`. PowerShell executing cmd.exe with explicit commands rather than through the PowerShell pipeline suggests the script author chose cmd.exe deliberately, which is a behavioral pattern worth tracking.

5. **EID 4103 (module invocation logging) combined with EID 4104 (script block)**: The presence of both events in the PowerShell channel indicates the test framework invoked PowerShell cmdlets with parameters. When EID 4103 events are present alongside anomalous parent-child process chains, they indicate active PowerShell interaction rather than simple script execution.

6. **whoami.exe before and after discovery tools**: The test framework pattern of `whoami.exe → tasklist.exe → whoami.exe` is a recognizable reconnaissance sequence. Detecting `whoami.exe` execution immediately before or after known discovery commands provides a broader behavioral context for the attack step.
