# T1552.006-2: Group Policy Preferences — Get-GPPPassword

## Technique Context

T1552.006 (Unsecured Credentials: Group Policy Preferences) covers adversary exploitation of
legacy GPP credential storage in SYSVOL. Test 2 uses the PowerSploit `Get-GPPPassword` function,
which is a purpose-built PowerShell tool that enumerates SYSVOL for GPP XML files containing
`cpassword` attributes and automatically decrypts them using the published AES key. Unlike test 1
(`findstr`), this tool performs the full attack — discovery plus decryption — in a single
PowerShell invocation. `Get-GPPPassword` has been part of PowerSploit since 2012 and remains
a standard tool in many penetration testing frameworks.

## What This Dataset Contains

The dataset captures the deployment and execution of `Get-GPPPassword.ps1` from the ART
external payloads directory.

**Sysmon EID 1 (Process Create) records the PowerShell invocation with the full command:**

```
"powershell.exe" & {. "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Get-GPPPassword.ps1"
Get-GPPPassword -Verbose}
```

Tagged with `technique_id=T1059.001`. A `whoami.exe` pre-check process is also present.

**PowerShell EID 4104 (Script Block Logging) captures both the test framework invocation and the
inner script block:**

```
& {. "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Get-GPPPassword.ps1"
Get-GPPPassword -Verbose}
```

The dot-sourcing of `Get-GPPPassword.ps1` loads the function into the session, after which
`Get-GPPPassword -Verbose` executes the SYSVOL enumeration and decryption. Because the ps1 file
is dot-sourced rather than run as a script, its internal content may be recorded as additional
script blocks if AMSI triggers re-logging; however, only the invocation wrapper appears in this
dataset, suggesting Defender intercepted or AMSI logged only the outer command.

**Security EID 4688** confirms the PowerShell process creation with command line, running as
SYSTEM from `C:\Windows\TEMP\`.

The dataset spans 36 Sysmon events, 10 Security events, and 49 PowerShell events over 5 seconds.

## What This Dataset Does Not Contain (and Why)

**No GPP credential output.** PowerShell stdout is not captured in Windows event logs. Whether
any GPP passwords were found and decrypted is not determinable. The ACME test domain was freshly
provisioned without legacy GPP password policies.

**No Get-GPPPassword function body in script block logs.** The `Get-GPPPassword.ps1` file is
dot-sourced from disk, not embedded in the command. Script block logging records the invocation
wrapper, but the function body from the ps1 file would only appear as additional blocks if
AMSI or script block logging captures the file load. The dataset's 49 PS events are dominated
by boilerplate internal error-handling closures from PowerShell session startup.

**No SYSVOL file access events.** Object access auditing is disabled. No EID 4663 events for
XML file reads appear. SMB network connections to the DC for SYSVOL traversal are not captured
in this Sysmon configuration.

**No Sysmon EID 11 (File Create).** `Get-GPPPassword` does not write output files; it returns
results to the pipeline. No artifacts are left on disk by the tool itself.

**No Sysmon EID 3 (Network Connect).** Although the tool accesses the SYSVOL share over SMB,
these connections are not represented in this Sysmon configuration's filtered output.

The Sysmon configuration uses include-mode filtering for Process Create; `powershell.exe` with
the ART test framework pattern is captured via the T1059.001 rule.

## Assessment

This dataset captures the invocation of a well-known GPP credential harvesting tool. The command
line fully identifies the attack intent — the path `ExternalPayloads\Get-GPPPassword.ps1` and the
`Get-GPPPassword` function name are both high-confidence indicators. The dataset does not record
whether any credentials were recovered, but the detection opportunity exists at the invocation
layer regardless of whether the domain has exploitable GPP files.

## Detection Opportunities Present in This Data

- **EID 4104 script block content**: `Get-GPPPassword` in any script block is a direct indicator.
  The function name, derived from PowerSploit, has near-zero legitimate use outside security
  testing.
- **EID 4688 / Sysmon EID 1 command line**: `Get-GPPPassword.ps1` in a PowerShell command line
  is observable without script block logging. Path patterns like `ExternalPayloads\` or
  `AtomicRedTeam\` are also strong secondary indicators.
- **Sysmon EID 1**: Any PowerShell process dot-sourcing a script named `*GPP*` or `*Password*`
  from unusual directories warrants investigation.
- **Combined with test 1 context**: If `findstr /S cpassword` (test 1) is followed by a
  `Get-GPPPassword` invocation, this represents progression through a complete GPP attack chain.
- **Execution as SYSTEM from TEMP**: The SYSTEM account running PowerShell with credential
  harvesting tools from `C:\Windows\TEMP\` is anomalous in most production environments.
