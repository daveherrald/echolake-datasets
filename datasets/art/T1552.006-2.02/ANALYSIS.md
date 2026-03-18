# T1552.006-2: Unsecured Credentials: Group Policy Preferences — GPP Passwords (Get-GPPPassword)

## Technique Context

T1552.006 covers adversary exploitation of legacy Group Policy Preferences (GPP) credential storage in Active Directory SYSVOL. When administrators deployed mapped drives, scheduled tasks, or local accounts via GPP, they could embed credentials directly in the XML policy files. Microsoft published the AES-256 key used to encrypt these `cpassword` fields in 2012 (MS14-025), making decryption trivial for anyone with access to SYSVOL.

Test 2 uses the PowerSploit `Get-GPPPassword` function — a purpose-built PowerShell tool that enumerates the domain SYSVOL share for GPP XML files containing `cpassword` attributes and automatically decrypts them using that published key. Unlike a `findstr`-based approach, `Get-GPPPassword` performs the complete attack: discovery, parsing, and decryption in a single invocation. It has been part of offensive PowerShell toolkits since 2012 and remains a standard step in many penetration testing methodologies.

This test ran on ACME-WS06 (a domain member of acme.local) with Microsoft Defender disabled.

## What This Dataset Contains

The dataset captures 166 total events across three channels: 39 Sysmon events, 123 PowerShell operational events, and 4 Security events.

**Sysmon EID 1 (Process Create) records the full PowerShell command executing Get-GPPPassword:**

```
CommandLine: "powershell.exe" & {. ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Get-GPPPassword.ps1""
Get-GPPPassword -Verbose}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The process was launched under `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`, with the parent PowerShell process (PID 17400) also running as SYSTEM. The script was loaded from the ART external payloads directory (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\Get-GPPPassword.ps1`) rather than being downloaded at runtime.

A second Sysmon EID 1 records `whoami.exe` executed as part of the ART test framework identity confirmation:

```
CommandLine: "C:\Windows\system32\whoami.exe"
User: NT AUTHORITY\SYSTEM
```

**Sysmon EID 7 (Image Load)** is the dominant event type — 25 entries capturing DLL loads into the PowerShell process. These are tagged with Sysmon rule names including `technique_id=T1055,technique_name=Process Injection` (standard PowerShell module loading) and `technique_id=T1574.002,technique_name=DLL Side-Loading`.

**Sysmon EID 10 (Process Access)** records four events of the parent PowerShell process (PID 17400) accessing child processes with `GrantedAccess: 0x1FFFFF` (full access). The call trace shows `ntdll.dll+a2854`, consistent with normal process creation mechanics. These events are tagged `technique_id=T1055.001,technique_name=Dynamic-link Library Injection` by the Sysmon ruleset.

**Sysmon EID 17 (Pipe Create)** records three named pipe creations including:

```
PipeName: \PSHost.134182416412301283.17400.DefaultAppDomain.powershell
```

These are standard PowerShell hosting infrastructure pipes, not attacker-controlled channels.

**Security EID 4688 (Process Create)** captures four process creation events with command-line auditing enabled. The key entry records:

```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {. ""C:\AtomicRedTeam\atomics\..\ExternalPayloads\Get-GPPPassword.ps1""  Get-GPPPassword -Verbose}
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**PowerShell EID 4104 (Script Block Logging)** captures 120 script block logging entries across three PowerShell instances. The samples in this dataset consist primarily of boilerplate PowerShell internal script blocks (`Set-StrictMode` error formatters) rather than the actual `Get-GPPPassword` function body, which was pre-loaded from the `.ps1` file on disk rather than inline. The EID 4103 module pipeline logging captures `Set-ExecutionPolicy Bypass -Scope Process -Force` execution and the test framework `Write-Host "DONE"` completion marker.

## What This Dataset Does Not Contain

**No SYSVOL network access events are present.** The dataset lacks Sysmon EID 3 (Network Connection) events that would show the PowerShell process connecting to the domain controller's SYSVOL share (typically `\\acme.local\SYSVOL` or `\\ACME-DC01\SYSVOL`). This is significant: the primary observable of the technique — reading GPP XML files from SYSVOL — is not directly captured in these logs. The absence could reflect that no GPP XML files with `cpassword` attributes existed in this lab environment's SYSVOL, that the network connection was not logged (SMB traffic to 192.168.4.10 may not have triggered the Sysmon network filter), or that `Get-GPPPassword` completed its enumeration without finding credentials to report.

**The `Get-GPPPassword` script body itself does not appear in script block logs.** The 120 EID 4104 events sampled are overwhelmingly boilerplate PowerShell internals. Because the script was loaded from a local file path (dot-sourced from `Get-GPPPassword.ps1`), the complete function code would appear in EID 4104 with the file path populated in the `Path:` field — but this event is not present in the sampled events.

**No credential output is recorded.** If `Get-GPPPassword` found and decrypted any `cpassword` values, the cleartext credentials would appear in PowerShell output but are not recorded in Windows event logs by default. There is no EID capturing what the tool actually returned.

**No registry or file system access events** (Sysmon EID 12/13/14) are present, consistent with GPP exploitation operating over SMB/SYSVOL rather than local file access.

## Assessment

With Defender disabled, `Get-GPPPassword` executes without interference. The dataset captures the process tree and execution context clearly: a SYSTEM-context PowerShell process running a script from the ART payloads directory. The absence of blocked or quarantined events means the execution timeline is preserved — in the defended variant, Defender terminates the process before meaningful execution, leaving only ART test framework.

The undefended dataset more faithfully represents what an actual attack against a domain environment with GPP password exposure would look like in telemetry. The attack itself — SYSVOL enumeration, XML parsing, AES decryption — runs to completion without process termination. The primary forensic gap in this dataset is the missing SYSVOL network access, which would normally be the strongest behavioral indicator linking the PowerShell process to Active Directory credential exposure.

The comparison between defended and undefended is instructive: the defended variant (49 PowerShell events, 36 Sysmon events, 10 Security events) had a comparable volume because Defender acts quickly but not before the process is recorded. The undefended variant (123 PowerShell events, 39 Sysmon events, 4 Security events) shows slightly more PowerShell activity from the tool's execution proceeding further, and slightly fewer Security events because Defender's own process creation (during remediation) is absent.

## Detection Opportunities Present in This Data

**Sysmon EID 1** provides the highest-confidence detection anchor: the command line `Get-GPPPassword` combined with execution from `C:\Windows\TEMP\` as `NT AUTHORITY\SYSTEM` is a strong behavioral indicator. The parent-child relationship (SYSTEM PowerShell spawning SYSTEM PowerShell from TEMP) is unusual for legitimate administrative activity.

**Security EID 4688** captures the same command line and is actionable for environments that have enabled process creation auditing with command-line logging (`Audit Process Creation` + `Include command line in process creation events` via Group Policy).

**PowerShell EID 4103 module logging** captures the `Set-ExecutionPolicy Bypass -Scope Process -Force` pattern, which consistently precedes ART test execution and signals that execution policy bypass is in use — a behavioral precursor worth correlating with subsequent credential access activity.

**Sysmon EID 17** pipe creation for `\PSHost.*` names in the SYSTEM context is a low-specificity but valid contextual indicator that a PowerShell hosting environment is active under SYSTEM privileges, which is unusual for standard workstation operations.

If SYSVOL network access events were present (Sysmon EID 3 showing PowerShell connecting to the DC on SMB port 445), the combination of `Get-GPPPassword` command line plus SMB connection to a domain controller would form a very high-confidence detection pair.
