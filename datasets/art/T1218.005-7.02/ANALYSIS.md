# T1218.005-7: Mshta — Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler

## Technique Context

T1218.005 (Mshta) is a defense evasion technique in which attackers abuse Microsoft's HTML Application Host (`mshta.exe`) to execute malicious scripts using a trusted, signed Windows binary. Mshta can execute `.hta` files containing JScript or VBScript, and critically it supports inline protocol handlers such as `about:` that allow script code to be passed directly on the command line without touching the filesystem. This variant goes further by routing execution through `rundll32.exe` rather than calling `mshta.exe` directly, adding a layer of indirection.

The technique is particularly attractive because `mshta.exe` and `rundll32.exe` are both signed Microsoft binaries present on every Windows installation. Application control solutions that trust these binaries by path or signature are vulnerable. Detection engineering traditionally focuses on `mshta.exe` process creation with suspicious command-line arguments, child processes spawned by `mshta.exe`, and network connections originating from it.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled, allowing the technique to execute without endpoint interference.

## What This Dataset Contains

The dataset spans 2026-03-17T16:56:24Z to 2026-03-17T16:56:27Z and contains 138 total events across three channels: 106 PowerShell, 4 Security, and 28 Sysmon.

**The test invocation is clearly captured.** Security EID 4688 records the child PowerShell process created to run the test with the full command line:

```
"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -UseRundll32 -Rundll32FilePath $env:windir\system32\rundll32.exe}
```

This is the Atomic Test Test framework (`Invoke-ATHHTMLApplication`) invoking mshta functionality via rundll32.

**PowerShell script block logging (EID 4104)** captures 105 events in the PowerShell/Operational channel. The overwhelming majority are boilerplate scriptblocks from the test framework infrastructure (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, `{ Set-StrictMode -Version 1; $this.Exception.InnerException.PSMessageDetails }`, etc.) rather than technique-specific content. The test framework command itself is captured in the Security channel rather than a dedicated 4104 event.

**Sysmon process creation (EID 1)** captures 4 process creations: two `whoami.exe` executions (the ATH framework's standard payload verification) and two PowerShell processes. One of the PowerShell EID 1 events shows the parent-child relationship:

- Parent: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (the test framework)
- Child: `powershell.exe` with the `Invoke-ATHHTMLApplication` command

**Sysmon image load (EID 7)** contributes 17 events documenting .NET runtime initialization in PowerShell processes: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, and Windows Defender scanning DLLs (`MpOAV.dll`, `MpClient.dll`).

**Sysmon process access (EID 10)** records 4 events of PowerShell accessing `whoami.exe` with `GrantedAccess: 0x1fffff` (full access rights).

**Sysmon named pipe creation (EID 17)** records 2 events for PowerShell host communication pipes (`\PSHost.134182401838366929.18324.DefaultAppDomain.powershell`).

**Sysmon file creation (EID 11)** records 1 event: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`, a normal PowerShell profile file.

## What This Dataset Does Not Contain

The dataset does not contain `mshta.exe` or `rundll32.exe` process creation events. Despite Defender being disabled, neither binary appears in Sysmon EID 1 or Security EID 4688. This is a **Sysmon configuration gap**, not a technique failure. The sysmon-modular configuration used in this environment operates in include-mode for ProcessCreate (EID 1), logging only processes that match explicit rules. `mshta.exe` and `rundll32.exe` are not in the include list for this configuration, so their process creation events are silently dropped.

The fact that `whoami.exe` executions appear (the ATH framework's success indicator) confirms the technique ran. The ATH framework spawns `whoami.exe` only after the target HTA execution completes. The mshta/rundll32 execution chain ran and succeeded — it simply was not captured by Sysmon's process creation filter.

There are no network connection events (Sysmon EID 3 or EID 22) because this test uses an inline `about:` protocol handler — no external network communication is required.

## Assessment

This dataset provides authentic process context around a successful Mshta+Rundll32 LOLBin execution with Defender disabled. The Security EID 4688 events capture the full `Invoke-ATHHTMLApplication` command line, and the `whoami.exe` execution confirms technique success. The gap in mshta/rundll32 process creation telemetry reflects a realistic Sysmon coverage limitation.

Compared to the defended variant (36 Sysmon, 10 Security, 45 PowerShell events), this undefended execution produced more PowerShell events (106) but similar Sysmon volume (28 vs. 36), consistent with Defender being absent — no MsMpEng.exe process scanning activity adds to the Sysmon 10 count here in the same way as the defended run.

## Detection Opportunities Present in This Data

**Security EID 4688 (Process Creation with command-line auditing):** The `Invoke-ATHHTMLApplication` command with `-UseRundll32 -Rundll32FilePath $env:windir\system32\rundll32.exe` and `-InlineProtocolHandler About` arguments is unambiguously malicious. Any PowerShell command line invoking `Invoke-ATHHTMLApplication` or referencing `mshta` alongside `rundll32` is worth immediate investigation.

**PowerShell EID 4104 (Script Block Logging):** Even though the primary command appears in Security rather than PowerShell logs, the presence of the ATH module infrastructure blocks (`Invoke-ATHHTMLApplication` references) in script block text would alert on any detection that looks for this function name.

**Sysmon EID 1 (Process Creation):** The `whoami.exe` execution with PowerShell as parent (`ParentCommandLine: powershell`) is captured and tagged with `technique_id=T1033` by the sysmon-modular rules. While not definitive alone, it contributes to a behavioral chain.

**Sysmon EID 10 (Process Access):** PowerShell accessing `whoami.exe` with `GrantedAccess: 0x1fffff` and the sysmon rule annotation `technique_id=T1055.001` is present. This is part of the ATH framework's access pattern and would appear in any run using this tooling.
