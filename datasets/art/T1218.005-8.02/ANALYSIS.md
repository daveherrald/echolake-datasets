# T1218.005-8: Mshta — Invoke HTML Application - JScript Engine with Inline Protocol Handler

## Technique Context

T1218.005 (Mshta) covers adversary abuse of Microsoft's HTML Application Host (`mshta.exe`) to execute malicious scripting code through a trusted signed binary. This test variant — number 8 in the T1218.005 series — uses `mshta.exe` directly (rather than the rundll32 indirection in test 7) with a JScript engine and the `about:` inline protocol handler. Passing script content via the `about:` handler means no `.hta` file touches the filesystem; the malicious code is embedded entirely within the command-line argument, complicating file-based detections.

This is one of the more common patterns seen in real intrusions. Defenders look for `mshta.exe` spawned with `about:` in the command line, unusual parent processes for `mshta.exe`, and child processes it spawns after executing the inline script.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset spans 2026-03-17T16:56:25Z to 2026-03-17T16:56:27Z and contains 150 total events: 108 PowerShell, 4 Security, and 38 Sysmon.

**The test command is recorded in Security EID 4688:**

```
"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}
```

This invokes the ATH framework's `Invoke-ATHHTMLApplication` function, which constructs and executes the actual `mshta.exe` command with an inline JScript payload via the `about:` handler.

**Sysmon EID 1 (Process Creation)** captures 4 events. Of note, a child PowerShell process is captured with the full `Invoke-ATHHTMLApplication` command line:

```
"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}
```

Parent: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (test framework), tagged with `technique_id=T1083` by sysmon-modular rules. Two `whoami.exe` executions are also captured — the ATH framework's standard success indicator that the HTA payload ran.

**Sysmon EID 10 (Process Access)** captures 4 events: PowerShell accessing both `whoami.exe` and a child PowerShell process with `GrantedAccess: 0x1fffff`.

**Sysmon EID 7 (Image Load)** contributes 25 events across multiple PowerShell processes. The second PowerShell process (the child spawning mshta) loads the same .NET runtime and Windows Defender DLLs as the test framework process: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, `MpOAV.dll`, `MpClient.dll`, `urlmon.dll`.

**Sysmon EID 17 (Pipe Created)** records 3 named pipe creation events for PowerShell host communication pipes in both the test framework and child PowerShell processes.

**Sysmon EID 11 (File Created)** records 2 events: `StartupProfileData-NonInteractive` and `StartupProfileData-Interactive` PowerShell profile files, both normal.

**PowerShell EID 4104** produces 107 script block events, predominantly test framework boilerplate (`Set-StrictMode`, `$_.PSMessageDetails`) and not the technique execution itself.

**Security EID 4688** records 4 process creation events including the whoami and the child PowerShell with the ATH command.

## What This Dataset Does Not Contain

No `mshta.exe` process creation appears anywhere in the dataset — not in Sysmon EID 1 nor Security EID 4688. As with the T1218.005-7 dataset, this is a Sysmon configuration gap: the sysmon-modular include-mode filter for ProcessCreate does not include `mshta.exe` as a monitored process, so its creation event is not logged.

The technique itself succeeded. The presence of two `whoami.exe` executions is the ATH framework's confirmation that `mshta.exe` ran its JScript payload. The mshta process executed and completed; it was simply invisible to Sysmon.

No network connections appear (Sysmon EID 3 or EID 22) because the `about:` inline protocol handler requires no external network communication.

No `.hta` file creation events (Sysmon EID 11) appear beyond the PowerShell profile writes, consistent with the inline `about:` approach — no temporary HTA file is written to disk.

## Assessment

This dataset documents a successful undefended Mshta JScript execution via inline protocol handler, with Defender absent throughout. Security EID 4688 captures the exact invocation, and the `whoami.exe` execution confirms technique success. The absence of `mshta.exe` from process creation logs is a known and documented coverage gap with sysmon-modular's include-mode filtering.

Compared to the defended variant (37 Sysmon, 11 Security, 45 PowerShell), this undefended run produced more PowerShell events (108) and more Sysmon events (38 vs. 37), largely due to the child PowerShell process spawned by the ATH framework generating additional image load events.

## Detection Opportunities Present in This Data

**Security EID 4688:** The child PowerShell command line `"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}` is a high-confidence indicator. Searching for `Invoke-ATHHTMLApplication` or for PowerShell command lines containing `mshta.exe` as a string argument is reliable.

**Sysmon EID 1:** Two `whoami.exe` executions with `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `ParentCommandLine: powershell` appear. Combined with the ATH command in Security logs, this completes the behavioral picture.

**Sysmon EID 10:** Process access from PowerShell to the child PowerShell process with full access (`0x1fffff`) is tagged `technique_id=T1055.001`. The PowerShell-to-PowerShell access pattern at this privilege level is unusual outside of specific tooling.

**PowerShell EID 4104:** The test framework infrastructure scriptblocks do not themselves contain `Invoke-ATHHTMLApplication`, but any detection that logs and searches for this function name in the script block text would catch the Security 4688 events' corresponding script block if full logging is enabled.
