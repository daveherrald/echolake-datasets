# T1218-2: System Binary Proxy Execution — Register-CimProvider Execute Evil DLL

## Technique Context

T1218 System Binary Proxy Execution encompasses techniques where attackers leverage legitimate, trusted Windows binaries to load and execute malicious code. Test 2 abuses `Register-CimProvider.exe`, a legitimate Windows Management Instrumentation (WMI) component located in `C:\Windows\SysWow64\`. This binary is designed to register CIM (Common Information Model) provider DLLs for WMI, but it can be repurposed to load an arbitrary DLL supplied via the `-Path` argument.

Because `Register-CimProvider.exe` is a signed Windows system binary, it can bypass application allowlisting controls that trust Microsoft-signed executables. The loaded DLL executes within the context of the `Register-CimProvider.exe` process, and any malicious capability in the DLL — persistence, reconnaissance, lateral movement — runs under the guise of a WMI administrative operation.

This test uses a pre-compiled test DLL (`T1218-2.dll`) from the Atomic Red Team repository, which demonstrates the loading mechanism without a destructive payload. The execution occurs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17T16:43:30Z–16:43:34Z) and contains 119 total events across three channels: 96 PowerShell events (95 EID 4104, 1 EID 4103), 5 Security events (all EID 4688), and 18 Sysmon events (9 EID 7 image loads, 4 EID 1 process creations, 4 EID 10 process access, 1 EID 17 named pipe).

The defining Sysmon EID 1 event captures `cmd.exe` with the command line: `"cmd.exe" /c C:\Windows\SysWow64\Register-CimProvider.exe -Path "C:\AtomicRedTeam\atomics\T1218\src\Win32\T1218-2.dll"`. The parent is the ART test framework `powershell` process running as SYSTEM. Sysmon tags this cmd.exe invocation as `technique_id=T1059.003,technique_name=Windows Command Shell`. The intermediate cmd.exe wrapper is typical of how Invoke-AtomicTest invokes command-line tools.

Two `whoami.exe` EID 1 events (tagged T1033) bookend the technique execution — the pre-test and post-test identity checks by the ART test framework.

The 9 Sysmon EID 7 image load events capture DLL loads into the process chain. These would include the standard system DLLs loaded by `Register-CimProvider.exe` as well as the test DLL itself, providing a DLL load sequence that characterizes this binary's execution profile.

PowerShell EID 4104 records are predominantly boilerplate engine internals. The one EID 4103 record covers the cleanup invocation: `Invoke-AtomicTest T1218 -TestNumbers 2 -Cleanup -Confirm:$false` — which is visible in the script block log as a direct artifact of the ART test framework.

The 4 Sysmon EID 10 events record full-access process handle opens (GrantedAccess: 0x1FFFFF) from the test framework PowerShell to the cmd.exe, Register-CimProvider.exe, and whoami.exe child processes — the standard ART test framework monitoring pattern.

Compared to the defended dataset (sysmon: 36, security: 12, powershell: 35), the undefended run captures roughly half as many Sysmon events (18 vs. 36) and fewer Security events (5 vs. 12). This reversal — fewer events in the undefended run — likely reflects that the defended dataset captures additional Defender-related process activity (scanner processes, remediation attempts) that inflates the event count.

## What This Dataset Does Not Contain

A Sysmon EID 1 process creation event for `Register-CimProvider.exe` itself is not present in the samples. While the cmd.exe invocation referencing it is captured, the child process creation when cmd.exe spawns Register-CimProvider.exe is not in the 20-event Sysmon sample. The full event stream would contain this record.

No Sysmon EID 7 image load event specifically identifying the test DLL (`T1218-2.dll`) is present in the samples. DLL load events for the specific malicious DLL would be the highest-value artifact for this technique, and while they exist in the raw stream the sample does not surface them explicitly.

No network, registry, or file creation events are present. The test DLL does not perform actions that generate those event types.

## Assessment

This dataset's central detection artifact — `Register-CimProvider.exe` loading an arbitrary DLL from an attacker-controlled path — is partially captured: the cmd.exe invocation with the full `-Path` argument pointing to `C:\AtomicRedTeam\atomics\T1218\src\Win32\T1218-2.dll` is present in Sysmon EID 1. This command line is the primary observable for this technique.

The path `C:\AtomicRedTeam\atomics\T1218\src\Win32\T1218-2.dll` is specific to the test environment, but in a real attack this would be any attacker-controlled DLL path — potentially in a user-writable directory, a network share, or a path that impersonates a legitimate system file. The detection value lies in the Register-CimProvider.exe binary being invoked with a `-Path` argument at all, since legitimate registration of CIM providers by administrators is rare and the binary's appearance in a process creation event warrants investigation.

The ART cleanup command visible in the PowerShell script block log (`Invoke-AtomicTest T1218 -TestNumbers 2 -Cleanup`) is a test framework artifact and would not appear in a real-world attack. Its presence here provides useful labeling for training and validation purposes.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — Register-CimProvider.exe with -Path argument:** The command line `C:\Windows\SysWow64\Register-CimProvider.exe -Path "<dll_path>"` is the defining signature of this technique. Legitimate use of this binary for actual WMI provider registration is rare in enterprise environments and should be treated as a high-priority investigation trigger.

**32-bit WMI utility invoked from 64-bit PowerShell:** The use of the `SysWow64` (32-bit) variant of Register-CimProvider.exe from a 64-bit PowerShell parent is consistent with testing or tooling that specifically targets the WoW64 subsystem to load 32-bit DLLs. This architecture mismatch between parent and child is worth noting.

**cmd.exe as intermediary between PowerShell and system administrative utilities:** The parent chain PowerShell → cmd.exe → Register-CimProvider.exe is more characteristic of scripted or automated execution than of manual WMI provider administration, which would typically be performed directly from an elevated command prompt or through dedicated WMI management tools.

**Sysmon EID 7 — DLL load path:** In the full event stream, the EID 7 image load event for the attacker-supplied DLL would show a load from a non-standard path into the Register-CimProvider.exe process. DLL loads into system processes from user-writable paths (temp directories, user profile paths, or paths outside `%SystemRoot%`) are strong indicators of this class of technique.
