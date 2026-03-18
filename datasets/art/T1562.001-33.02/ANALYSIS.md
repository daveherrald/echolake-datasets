# T1562.001-33: Disable or Modify Tools — LockBit Black - Use Registry Editor to Turn On Automatic Logon (cmd)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) covers registry
modifications that alter security-relevant system behavior. This test replicates a LockBit
Black technique that configures Windows automatic logon by writing credentials into the
registry under `HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon`.

Automatic logon bypasses the interactive authentication requirement at boot. Ransomware
operators configure it so that after forcing a reboot (which precedes or follows encryption),
the system automatically logs in and the ransomware payload can resume execution without
requiring a user to enter credentials. This technique sets four values:

- `AutoAdminLogon` = 1 (enables automatic logon)
- `DefaultUserName` = Administrator
- `DefaultDomainName` = contoso.com
- `DefaultPassword` = password1

These are the ART test defaults. In a real intrusion, the adversary would substitute their
own or the compromised account's credentials.

This is the `cmd.exe` + `reg.exe` variant. The PowerShell-native `New-ItemProperty` variant
is test 35. Comparing the two shows different telemetry profiles for the same outcome.

In this **undefended** dataset, Defender is disabled. The registry writes succeed.

## What This Dataset Contains

The dataset captures 63 events across two channels (56 PowerShell, 7 Security) spanning
approximately 5 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Seven process creation events capturing the full attack chain.** The
sequence is:

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. `"cmd.exe" /c reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f & reg add ... /v DefaultUserName /t REG_SZ /d Administrator /f & reg add ... /v DefaultDomainName /t REG_SZ /d contoso.com /f & reg add ... /v DefaultPassword /t REG_SZ /d password1 /f` (single cmd.exe invocation chaining four reg.exe calls via `&`)
3. `reg  add "HKLM\...\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 1 /f`
4. `reg  add "HKLM\...\Winlogon" /v DefaultUserName /t REG_SZ /d Administrator /f`
5. `reg  add "HKLM\...\Winlogon" /v DefaultDomainName /t REG_SZ /d contoso.com /f`
6. `reg  add "HKLM\...\Winlogon" /v DefaultPassword /t REG_SZ /d password1 /f`
7. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)

The full credential set — `Administrator`, `contoso.com`, `password1` — appears in
plaintext in the `reg.exe` 4688 command lines. This is the defining characteristic of this
technique's telemetry: credentials are written via command line and therefore logged in
process creation events if command line auditing is enabled.

The parent for `cmd.exe` is the ART test framework PowerShell running as `NT AUTHORITY\SYSTEM`.
Note that `DefaultPassword` is stored in plaintext in the registry key, meaning credentials
are exposed both at write time (in 4688) and at rest (in the registry).

**PowerShell EID 4104 — 55 script block events.** The substantive block is the cleanup
invocation:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 33 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

ART test framework boilerplate (`Set-ExecutionPolicy Bypass`, `$ErrorActionPreference`) is present.
The `reg add` commands execute in `cmd.exe` and do not appear as 4104 blocks.

**PowerShell EID 4103 — One module pipeline event** for `Set-ExecutionPolicy`.

**No EID 4100 error events.** All four `reg.exe` operations completed successfully.

## What This Dataset Does Not Contain

**No Sysmon events.** Sysmon is not in the bundled channels. The defended dataset captures
the process creates for `cmd.exe` and the four `reg.exe` invocations as Sysmon EID 1, with
Security 4689 exit events confirming `0x0` exit status for all four. The process tree
data is absent here.

**No Sysmon EID 13 (registry value set).** The Winlogon policy key
`HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon` is not in the
sysmon-modular EID 13 include rules. The only evidence of the registry modification is the
`reg.exe` command lines in 4688.

**No logon events showing automatic logon active.** The ART test writes the registry values
but the system is not rebooted as part of the test, so no Security 4624 auto-logon event
appears to confirm the configuration took effect.

**No cleanup events in the 4688 stream.** Unlike test 32, which included explicit `reg
delete` cleanup events, this dataset's 7 Security events cover only the attack phase and
identity checks. The ART cleanup for test 33 runs via `Invoke-AtomicTest -Cleanup` (the
4104 block), but no separate `reg delete` 4688 events appear in the samples — the cleanup
phase's process creates may not have been collected within the dataset's time window.

## Assessment

This dataset provides one of the most forensically rich examples in this batch: a
plaintext credential write to the registry captured in Security 4688 command lines. All
four `reg.exe` invocations appear individually as separate 4688 events, making the full
autologon configuration visible: the account name (`Administrator`), domain (`contoso.com`),
and password (`password1`) in cleartext.

In the defended variant, this technique also succeeds — the HKLM Winlogon policy key is
not protected by Tamper Protection. The defended and undefended datasets produce essentially
equivalent Security 4688 evidence. The defended variant additionally includes Sysmon process
tree data and Security 4689 exit code confirmation.

This technique is notable because it stores a password in plaintext in HKLM, creating
a credential exposure risk beyond the initial attack objective. Any process with read access
to that registry key can retrieve the password.

## Detection Opportunities Present in This Data

**Security EID 4688 — `reg.exe` writing to the Winlogon policy key with `AutoAdminLogon`,
`DefaultUserName`, `DefaultDomainName`, and `DefaultPassword`.** All four values appear
in the command lines. The `DefaultPassword` write is particularly high-fidelity: writing a
plaintext password to the Winlogon registry key is not a legitimate administrative pattern
in a domain-joined environment.

**Security EID 4688 — Credential values in `reg.exe` command lines.** The username
`Administrator`, domain `contoso.com`, and password `password1` appear in cleartext in the
process creation log. SIEM rules that extract and alert on password-like strings in
`reg.exe` command lines targeting Winlogon paths can identify this technique in real time.

**Security EID 4688 — `cmd.exe` chaining four `reg add` commands with `&`.** The long
single-line `cmd.exe` invocation chaining four `reg add` calls is visually distinct and
behaviorally unusual for legitimate administration. The full chain in one 4688 event
contrasts with the four separate `reg.exe` 4688 events that follow.

**Security EID 4688 — PowerShell → cmd.exe → reg.exe chain as SYSTEM targeting HKLM
Winlogon.** SYSTEM writing credential-related values to HKLM via a PowerShell → cmd.exe
→ reg.exe chain is not a normal system administration pattern and represents a reliable
behavioral indicator.
