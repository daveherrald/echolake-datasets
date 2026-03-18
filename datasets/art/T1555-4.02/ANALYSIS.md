# T1555-4: Credentials from Password Stores — Enumerate Credentials from Windows Credential Manager Using vaultcmd.exe (Windows Credentials)

## Technique Context

T1555 covers credential theft from password stores. This test uses `vaultcmd.exe`, a legitimate Windows built-in utility, to enumerate the Windows Credentials vault. Unlike the PowerShell-based tests (T1555-2 and T1555-3), `vaultcmd.exe` is a Living Off the Land Binary (LOLBin) — it is a signed, Microsoft-issued tool shipped as part of Windows with no offensive reputation. The command `vaultcmd /listcreds:"Windows Credentials" /all` enumerates all stored credentials and outputs them including metadata and, for some credential types, the stored values.

This LOLBin approach has a lower detection footprint than importing custom PowerShell scripts from GitHub. The binary already exists on every Windows installation, leaves no network trace, and its use for administrative inspection is a plausible cover story.

This test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 156 total events: 41 Sysmon events, 107 PowerShell operational events, 7 Security events, and 1 Application event.

**Sysmon EID 1 (Process Create)** captures five process creation events. The key entries show the process chain:

```
CommandLine: "powershell.exe" & {vaultcmd /listcreds:""Windows Credentials"" /all}
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

```
CommandLine: "C:\Windows\system32\VaultCmd.exe" "/listcreds:Windows Credentials" /all
Image: C:\Windows\System32\VaultCmd.exe
User: NT AUTHORITY\SYSTEM
RuleName: technique_id=T1083,technique_name=File and Directory Discovery
```

The PowerShell command invokes `vaultcmd` as a shell command (not via `Start-Process` or `Invoke-Expression`), and the child `VaultCmd.exe` process is recorded with its full argument string. Both run as `NT AUTHORITY\SYSTEM`.

**Security EID 4688** captures five process creation events with full command-line auditing:

```
Process Command Line: "powershell.exe" & {vaultcmd /listcreds:""Windows Credentials"" /all}
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

```
Process Command Line: "C:\Windows\system32\VaultCmd.exe" "/listcreds:Windows Credentials" /all
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The Security channel records both the parent PowerShell invocation and the direct `VaultCmd.exe` execution.

**Security EID 5379 (Credential Manager credentials were read):**

```
Subject: Security ID: S-1-5-18 (NT AUTHORITY\SYSTEM)
Account Name: ACME-WS06$
Read Operation: Enumerate Credentials
```

This is a significant event: Security EID 5379 is the dedicated Windows audit event for Credential Manager enumeration. Its presence here (and absence in T1555-2 and T1555-3) indicates that `vaultcmd.exe` triggers this audit event, while the PowerShell P/Invoke approach in those tests does not. This demonstrates a meaningful difference in detection coverage depending on the enumeration method used.

**Security EID 5381 (Vault credentials were read):**

```
Subject: Security ID: S-1-5-18 (NT AUTHORITY\SYSTEM)
Account Name: ACME-WS06$
```

EID 5381 records vault-level credential enumeration, complementing EID 5379. Together, these two events provide direct evidence that credential vault access occurred, independent of the process creation record.

**Sysmon EID 7** accounts for 25 events (DLL loads). EID 10 captures 5 process access events. EID 11 captures 3 file creation events. EID 17 captures 3 pipe creation events.

**PowerShell EID 4104** captures 104 script block events (EID 4103 has 3 events). No network-download events are present — this test is entirely local.

## What This Dataset Does Not Contain

**No network connection events.** `vaultcmd.exe` is a local binary and makes no network calls. This distinguishes T1555-4 from T1555-2 and T1555-3.

**The actual credential output from vaultcmd is not logged.** The text output of `vaultcmd /listcreds:"Windows Credentials" /all` — which would show credential names, target URLs, and potentially plaintext values — is not captured in any event channel.

**No PowerShell script block logging of offensive tooling.** Unlike T1555-2/3, there is no remote script loaded into memory. The EID 4104 events are entirely boilerplate, which is actually a higher-fidelity representation of the LOLBin approach — there is less PS telemetry precisely because no scripted payload is involved.

**No Sysmon file access events** for the credential store files under `%LOCALAPPDATA%\Microsoft\Credentials`.

## Assessment

T1555-4 is the most detection-rich test in the T1555 series, not because it generates more events, but because it generates the right events. The Security EID 5379 and EID 5381 events provide dedicated, purpose-built audit evidence of Credential Manager access — evidence that is entirely absent from the PowerShell-based approaches in T1555-2 and T1555-3. This is a meaningful empirical finding: the same credential vault can be enumerated via different methods, and the Windows audit trail differs significantly depending on which method is used.

The LOLBin angle cuts both ways for detection: `vaultcmd.exe` has a lower profile than downloading scripts from GitHub, but it triggers more specific security audit events. An adversary choosing between these approaches faces a tradeoff.

Compared to the defended variant (38 Sysmon, 37 PowerShell, 12 Security), the undefended dataset shows similar Sysmon counts (41 vs 38), more PowerShell events (107 vs 37), and fewer Security events (7 vs 12) — the difference in Security events may reflect Defender's own process activity in the defended run generating additional EID 4688 events.

The 5 Sysmon EID 10 events (versus 4 in most other T1555 tests) reflect one additional process access, likely from PowerShell accessing the VaultCmd child process.

## Detection Opportunities Present in This Data

**Sysmon EID 1** captures `VaultCmd.exe "/listcreds:Windows Credentials" /all` as a child of `powershell.exe` running as SYSTEM. `vaultcmd.exe` executing with credential enumeration arguments is unusual on workstations. The parent PowerShell process running from `C:\Windows\TEMP\` as SYSTEM is an additional behavioral flag.

**Security EID 4688** records both the PowerShell invocation and the direct `VaultCmd.exe` command line with full argument visibility.

**Security EID 5379** is the most specific and highest-value detection event in this dataset: it directly records that Credential Manager credentials were enumerated under the SYSTEM account (`ACME-WS06$` machine account). EID 5379 requires the `Audit Other System Events` or `Audit Credential Validation` subcategory to be enabled, but when present, it provides unambiguous evidence of vault access.

**Security EID 5381** similarly records vault-level access. The combination of EID 5379 + EID 5381 in the same session, preceded by a `VaultCmd.exe` process creation (EID 4688), forms a three-event detection chain that is difficult to explain through legitimate administrative activity on a workstation.

The absence of Security EID 5379 in T1555-2 and T1555-3 means that detection coverage for Credential Manager enumeration depends on which method the attacker uses — this dataset is valuable evidence for that coverage gap.
