# T1112-4: Modify Registry — Use PowerShell to Modify Registry to Store Logon Credentials

## Technique Context

T1112 (Modify Registry) combined with credential access is one of the more operationally significant registry modifications an attacker can make. This test sets the `UseLogonCredential` value to `1` under `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. When this value is set, Windows caches plaintext credentials in LSASS memory — a behavior that was disabled by default starting with Windows 8.1 and KB2871997. Enabling it explicitly reverts that protection.

WDigest is a legacy authentication protocol. On modern systems, it is disabled to prevent plaintext credential storage. An attacker who gains SYSTEM access and sets `UseLogonCredential=1` is staging the system for credential harvesting: the next time any user authenticates, their plaintext password will be stored in LSASS memory and becomes recoverable by tools like Mimikatz. This makes T1112-4 a preparation step that directly enables T1003 (OS Credential Dumping). The two techniques are frequently chained in real-world intrusions.

Sysmon's threat intelligence tagging in this dataset explicitly labels the registry write with `technique_id=T1003,technique_name=Credential Dumping`, confirming that the sysmon-modular ruleset treats WDigest registry manipulation as a credential-access indicator.

In the defended variant, this dataset produced 47 Sysmon, 12 Security, and 38 PowerShell events. The undefended capture produced 27 Sysmon, 3 Security, and 40 PowerShell events. The undefended Sysmon count is lower because the defended run generated additional Defender-related process activity; Security events are fewer because the test used native PowerShell rather than cmd.exe/reg.exe, reducing the process creation count.

## What This Dataset Contains

The core evidence is a direct registry write captured in Sysmon EID 13, tagged with `technique_id=T1003,technique_name=Credential Dumping`:

```
Registry value set:
RuleName: technique_id=T1003,technique_name=Credential Dumping
TargetObject: HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
Details: 1
User: NT AUTHORITY\SYSTEM
```

This event is written by PowerShell (PID 2392), not by `reg.exe`. The technique uses `Set-ItemProperty` directly from a PowerShell subprocess.

Sysmon EID 1 captures that subprocess's process creation with the full command line:

```
"powershell.exe" & {Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1' -ErrorAction Ignore}
```

This PowerShell process (PID 2392) was spawned by the ART test framework PowerShell process (PID 6368). Security EID 4688 also records this child PowerShell creation with the full command line showing `Set-ItemProperty`.

PowerShell EID 4104 (script block logging) captures the technique command:

```
& {Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '1' -ErrorAction Ignore}
```

PowerShell EID 4103 (module logging) records the `Set-ItemProperty` cmdlet execution with its parameters — this is one of only two datasets in this batch that includes EID 4103, providing particularly detailed PowerShell execution context.

Sysmon EID 11 (file created) records PowerShell writing `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`, which is a normal PowerShell initialization artifact rather than a technique artifact.

## What This Dataset Does Not Contain

The dataset does not show any subsequent credential harvesting activity. The registry modification prepares LSASS to store plaintext credentials, but no tool reads from LSASS in this dataset. The practical impact of the WDigest change only materializes at the next user authentication event, which is outside this capture window.

There are no authentication events, no LSASS access events, and no Sysmon EID 10 targeting `lsass.exe`. The prep work is recorded; the exploitation is not.

The dataset does not show the initial ART test framework PowerShell process (PID 6368) in a Sysmon EID 1 event — only the child PowerShell that executed the technique command is captured in process creation telemetry.

## Assessment

This dataset provides the richest multi-layer evidence of any test in this batch. The registry write itself is directly recorded in Sysmon EID 13, the process creation with the full PowerShell command line appears in both Security EID 4688 and Sysmon EID 1, and the PowerShell script block (EID 4104) plus module logging (EID 4103) provide independent confirmation of exactly what cmdlet was called with which parameters.

This is a case where every detection layer fires simultaneously: registry monitoring, process creation auditing, and PowerShell logging all capture the same action. An analyst working from any one of these sources would find the indicator; working from all three provides corroboration that makes false positive dismissal difficult.

The technique executes cleanly in the undefended environment. There is no blocking, no retry behavior, and no error output visible in the PowerShell logging. The `Set-ItemProperty` call used `-ErrorAction Ignore`, which would suppress output on failure — but the Sysmon EID 13 confirms the write succeeded.

## Detection Opportunities Present in This Data

**Sysmon EID 13 on WDigest.** A registry write to `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` should trigger an immediate alert. This is a targeted, specific indicator with essentially no legitimate administrative use case for post-deployment modification.

**PowerShell EID 4104 script block containing `UseLogonCredential`.** The script block text is unobfuscated and contains the registry path and value name literally. Script block logging captures this regardless of whether the PowerShell session was interactive or launched from another script.

**PowerShell EID 4103 `Set-ItemProperty` with WDigest path.** Module logging records the exact parameter binding, confirming both the path and the value `1`. This is an additional corroborating source beyond script block logging.

**Child PowerShell spawned with `& {Set-ItemProperty...}` inline command.** Spawning a PowerShell subprocess with an inline script block containing `Set-ItemProperty` targeting `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders` is an unusual pattern worth flagging regardless of the specific value being modified.

**SYSTEM-context registry writes to SecurityProviders.** The `NT AUTHORITY\SYSTEM` token combined with the `SecurityProviders` registry path indicates elevated, non-interactive access to authentication configuration — an access pattern worth monitoring broadly.
