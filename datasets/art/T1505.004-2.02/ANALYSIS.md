# T1505.004-2: IIS Components — Install IIS module using PowerShell cmdlet New-WebGlobalModule

## Technique Context

T1505.004 (IIS Components) covers adversary use of IIS extensibility mechanisms to achieve persistent server-side execution. IIS native modules are DLLs loaded into every IIS worker process (`w3wp.exe`) on each web request, providing an attacker with persistent code execution tied to web server activity. This test uses the `WebAdministration` PowerShell module's `New-WebGlobalModule` cmdlet to register a global IIS native module — meaning the DLL would load into all IIS application pools, not just one site.

Test T1505.004-2 calls:

```powershell
New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll
```

This registers the legitimate `defdoc.dll` (the IIS Default Document module) under a new name, which would normally load it again into all worker processes. The use of a legitimate IIS DLL as the registered image means the DLL itself is not malicious — the technique demonstrates the registration mechanism. In a real attack, a malicious DLL would be specified instead.

The test requires IIS to be installed. In the defended variant, IIS was not installed on this workstation, so `New-WebGlobalModule` threw an exception; the same outcome occurs in this undefended dataset. Neither variant captures actual IIS module loading or `applicationHost.config` modification.

## What This Dataset Contains

**Security EID 4688** provides the primary evidence. The ART test framework PowerShell spawns a child `powershell.exe` process with:

```
"powershell.exe" & {New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll}
```

This command line is the complete attack payload: the `WebAdministration` cmdlet with the module name and DLL path as named parameters. The child PowerShell process runs and the test framework captures its output. The cleanup invocation is also present:

```
"powershell.exe" & {Remove-WebGlobalModule -Name DefaultDocumentModule_Atomic}
```

The `Remove-WebGlobalModule` call in the cleanup phase would remove the registration if it succeeded. Since IIS is not installed, neither the add nor the remove takes effect, but both command lines are captured.

**Sysmon EID 1** captures the child `powershell.exe` with the `New-WebGlobalModule` command. The sysmon-modular ruleset tags this event with `technique_id=T1083` (File and Directory Discovery) because the command line contains `%windir%\system32\inetsrv` — the rule matches the inetsrv path as a suspicious directory reference. This is a false-positive tag (the correct technique is T1505.004), but the event is captured.

The cleanup `Remove-WebGlobalModule` invocation also appears in Security EID 4688 as a separate child `powershell.exe` process. A `whoami.exe` EID 4688/Sysmon EID 1 event brackets the test.

**Sysmon EID 7** (ImageLoad): 25 image load events document the PowerShell, .NET, and WebAdministration module assembly stack. The elevated count (25 events vs. ~9 for simple tests) reflects the `WebAdministration` module loading its IIS-related assemblies during the `New-WebGlobalModule` call, even though IIS is not installed. The `WebAdministration` module is present on the system as part of the Windows feature infrastructure even without IIS being fully installed.

**Sysmon EID 17**: Three named pipe events for PowerShell host pipes (`\PSHost.*.DefaultAppDomain.powershell`), one for each PowerShell session (parent, child add, child remove).

**Sysmon EID 10**: Four process access events from the test framework PowerShell monitoring child processes.

**Sysmon EID 11** (FileCreate): One file creation event — the PowerShell profile write to `StartupProfileData-NonInteractive`. There is no `applicationHost.config` write event here because IIS is not installed.

The PowerShell channel (117 events: 115 EID 4104 + 2 EID 4103) is the largest of any test in this batch and contains primarily test framework boilerplate. The high count may reflect the WebAdministration module loading generating additional script block evaluations.

**Compared to the defended variant** (46 Sysmon / 10 Security / 45 PowerShell): The undefended run has fewer Sysmon events (38 vs. 46) but significantly more PowerShell events (117 vs. 45). The defended variant's higher Sysmon count is unexpected since IIS is not installed in either run — it may reflect Defender generating additional process access and image load events during its inspection. The PowerShell count difference (117 vs. 45) in the undefended run is substantial and likely reflects PowerShell loading more of the WebAdministration module stack when Defender is not terminating the process early. Since neither run installs the module (IIS not present), the Security event counts are similar (4 vs. 10).

## What This Dataset Does Not Contain

IIS is not installed on ACME-WS06, so `New-WebGlobalModule` throws an error rather than writing to `applicationHost.config`. There are no Sysmon EID 11 events showing a configuration file write to `%SystemRoot%\System32\inetsrv\config\applicationHost.config` — the primary artifact of a successful IIS module installation. There are no `w3wp.exe` process creation events, no IIS DLL image loads (`defdoc.dll` loading into a worker process), and no IIS access log entries. The PowerShell EID 4104 logs do not show the `New-WebGlobalModule` function body in the sampled events.

## Assessment

This dataset captures the command-line evidence of an IIS global module registration attempt with the full cmdlet invocation in Security EID 4688 and Sysmon EID 1. The `New-WebGlobalModule` command with `-Image %windir%\system32\inetsrv\defdoc.dll` is the highest-fidelity indicator available here. The absence of `applicationHost.config` modification means this dataset cannot support behavioral analytics based on IIS configuration changes — only the invocation attempt.

For teams building detection on `WebAdministration` cmdlet abuse, the EID 4104 script block logs and Security EID 4688 command line provide the detection surface. The T1083 rule tagging by sysmon-modular (matching `inetsrv` in the command line) is a false-positive but demonstrates that the path string is observable in process creation metadata.

A dataset with IIS installed would add: `applicationHost.config` write (Sysmon EID 11), potential IIS configuration manager process events, and — after the module is registered and a web request is made — `defdoc.dll` loading into `w3wp.exe` (Sysmon EID 7). Those artifacts are the actual persistence mechanism and are absent here.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: `powershell.exe` command line containing `New-WebGlobalModule` with a `-Image` path is a direct and high-confidence indicator. This cmdlet is not used in normal Windows administration outside of IIS module management, and module registration via this method is anomalous on workstations.
- **Security EID 4688**: The `-Image` path pointing to `%windir%\system32\inetsrv\` using a legitimate IIS DLL is the specific pattern in this test. In a real attack, the `-Image` path would point to a malicious DLL — monitoring for `New-WebGlobalModule -Image` with any non-standard path is the detection target.
- **Sysmon EID 1**: `powershell.exe` tagged `T1083` (false positive from the `inetsrv` path match) — the sysmon-modular rule fires on the `inetsrv` directory reference even though the technique classification is T1505.004. The event is still captured and actionable.
- **Security EID 4688**: The cleanup `Remove-WebGlobalModule -Name DefaultDocumentModule_Atomic` invocation following the add — the module name `DefaultDocumentModule_Atomic` is an ART artifact. Real attackers would choose a less obvious module name, but the `Remove-WebGlobalModule` following a `New-WebGlobalModule` in the same session is a behavioral signal.
- **EID 4104 Script Block Logging**: If the `New-WebGlobalModule` execution is captured in script block logs (as it would be in environments with broader PS logging), the cmdlet name and `-Image` path are visible. Alerting on `New-WebGlobalModule` in any script block context would be low-volume and high-fidelity.
