# T1218.007-6: Msiexec — WMI Win32_Product Class Execute Local MSI with Embedded VBScript

## Technique Context

T1218.007-6 combines two distinct evasion techniques: it uses WMI's `Win32_Product` class to invoke `msiexec.exe` programmatically, and the MSI being installed contains an embedded VBScript custom action. The WMI layer adds indirection — rather than calling `msiexec.exe` directly from a command line, PowerShell invokes `Invoke-CimMethod` on `Win32_Product.Install()`, which internally triggers Windows Installer. This approach can evade detections focused solely on `msiexec.exe` command-line patterns, since the process creation ancestry looks different.

The `Win32_Product` class is known to trigger a "consistency check" that can re-advertise or repair existing MSI installations as a side effect, and this behavior has been observed in enterprise environments — making its use less anomalous than in non-enterprise contexts.

The embedded VBScript payload executes during the custom action phase of installation, running inside the `msiexec.exe` process context and spawning a child process (`powershell.exe`) to demonstrate execution.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

This is the largest dataset in the T1218.007 group, with 189 total events: 115 PowerShell, 6 Security, 62 Sysmon, and 6 Application. The high Sysmon count reflects the richer process activity from WMI-initiated installation spawning a second PowerShell process for the VBScript payload.

**Security EID 4688 records the full process chain:**

1. `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_VBScript.msi' }}` — the WMI-triggered install command
2. `C:\Windows\System32\MsiExec.exe -Embedding A40BF8A2646923E26BCD8CB8CF1AC3C8 E Global\MSI0000` — the embedding worker process
3. `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host VBScript executed me!; exit` — VBScript payload's spawned process
4. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification
5. `"powershell.exe" & {}` — test framework cleanup

Unlike the direct msiexec invocations in T1218.007-1 and -4, there is no `cmd.exe` in the chain — `Invoke-CimMethod` directly spawns the child PowerShell that calls msiexec internally.

**Sysmon EID 1** captures the child PowerShell process creation:

```
CommandLine: "powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_VBScript.msi' }}
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
RuleName: technique_id=T1059.001
```

Also captured: `msiexec.exe` (`RuleName: technique_id=T1218`) spawning PowerShell (`-nop -Command Write-Host VBScript executed me!; exit`).

**Sysmon EID 7 (Image Load)** produces 43 events — the highest in this group. The second PowerShell process (spawned by WMI) triggers its own full .NET runtime DLL load sequence, approximately doubling the image load events. Scripting DLLs loaded in the msiexec embedding process (`vbscript.dll`, `wshom.ocx`, `scrrun.dll`) are not visible in the 20 sampled events, but the process chain confirms they loaded.

**Sysmon EID 17 (Pipe Created)** records 4 events for PowerShell host communication pipes across two PowerShell processes.

**Sysmon EID 11 (File Created)** records 5 events. One notable entry shows `svchost.exe` writing to `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat`, tagged `technique_id=T1574.010` — ambient system activity unrelated to the test.

**Sysmon EID 10 (Process Access)** records 4 events including PowerShell-to-PowerShell full access, reflecting the WMI-spawned process chain.

**Application log** records the complete Windows Installer lifecycle: EID 1040, 1033 (success), 11707, 10000, 10001, 1042 — confirming successful VBScript MSI installation.

**PowerShell EID 4104** captures test framework boilerplate and the VBScript payload command: `Write-Host VBScript executed me!; exit` in the spawned PowerShell's script block logging.

## What This Dataset Does Not Contain

No network events appear, consistent with a local MSI installation requiring no external connectivity.

No Sysmon events capture the VBScript execution itself inside the `msiexec.exe` embedding process. VBScript runs in-process within the Windows Script Host runtime; only the side effect (spawning PowerShell) is visible externally.

No registry events capture WMI operations or the MSI product registration.

## Assessment

This dataset provides rich process chain telemetry for a WMI-initiated Msiexec LOLBin attack with embedded VBScript. The full execution is confirmed by the PowerShell payload process and `whoami.exe` execution. The WMI invocation pattern produces a distinct process ancestry (`powershell.exe → powershell.exe → msiexec.exe`) that differs from direct msiexec command-line invocations.

Compared to the defended variant (58 Sysmon, 16 Security, 51 PowerShell, 6 Application), this undefended run produced slightly more Sysmon events (62 vs. 58) and fewer Security events (6 vs. 16). The defended run's higher Security count comes from Defender-generated privilege audit events accompanying the msiexec install.

## Detection Opportunities Present in This Data

**Security EID 4688:** The command line `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_VBScript.msi' }}` is unambiguous. In real attacks: PowerShell invoking `Invoke-CimMethod` on `Win32_Product` to install MSIs is rare and should be investigated.

**Sysmon EID 1:** `msiexec.exe` spawning `powershell.exe -nop -Command Write-Host VBScript executed me!; exit` is captured and highly anomalous. Real software MSI custom actions do not spawn PowerShell with arbitrary inline commands. The `-nop` flag suppressing the profile is a common attacker technique.

**PowerShell EID 4104:** The script block `Write-Host VBScript executed me!; exit` logged in the spawned PowerShell process. The script block ID can be correlated with the Security 4688 process creation event for the same PowerShell process to establish execution context.

**Sysmon EID 7 (Image Load):** The high image load count (43 events) reflects two full PowerShell initialization sequences. The second PowerShell process (spawned by WMI) loading Windows Defender DLLs in the undefended environment is interesting — Defender DLLs load in PowerShell even when the Defender service is disabled, because the DLLs are part of the PowerShell AMSI integration.
