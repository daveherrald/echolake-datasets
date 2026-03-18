# T1564-3: Hide Artifacts — With a Space on the End

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) encompasses methods adversaries use to prevent artifacts from being noticed. This test creates a local Windows account named `Administrator ` — a trailing space appended to the built-in administrator account name. The name is visually indistinguishable from the real `Administrator` account in many display contexts, including some GUI tools and log parsers that trim whitespace. Unlike the dollar-sign variant (T1564-2), this technique requires the PowerShell `New-LocalUser` cmdlet rather than `net user`, since net.exe strips trailing spaces.

The technique is effective against defenders who visually scan user lists or alert on exact string matches to `Administrator` without accounting for trailing whitespace.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:18:54–14:19:00 UTC).

**Process execution chain (Sysmon EID 1):**

The ART test framework launched PowerShell via the QEMU guest agent. The Sysmon process create record shows the full command line:

```
"powershell.exe" & {New-LocalUser -Name "Administrator " -NoPassword}
```

The trailing space is preserved verbatim in the logged command line. A preparatory `whoami.exe` (T1033) was also captured.

**PowerShell EID 4104:** Script block logging captured the attack payload directly:

```
& {New-LocalUser -Name "Administrator " -NoPassword}
{New-LocalUser -Name "Administrator " -NoPassword}
```

Both the outer invocation wrapper and the inner script block are present, logged as separate script block IDs. The trailing space is preserved in both.

A separate script block records loading of the PowerShell profile from `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`.

**Security EID 4688/4689:** Process creation and exit for powershell.exe, conhost.exe, and whoami.exe, all running as SYSTEM (S-1-5-18).

**Security EID 4703:** Token right adjustment for the SYSTEM account.

**Sysmon EID 7:** DLL loads for the PowerShell instance annotated with T1055 and T1059.001 rule names.

**Sysmon EID 17:** Named pipe `\PSHost.*.powershell` created by the PowerShell process.

**Sysmon EID 10:** PowerShell cross-process access to whoami.exe with `GrantedAccess: 0x1FFFFF`.

## What This Dataset Does Not Contain (and Why)

**No account management events (4720, 4726, 4738):** Account management auditing is disabled (`account_management: none`). The SAM account creation is not logged in the Security channel. There is no Windows event confirming whether the account was actually created or whether the name uniqueness check rejected a duplicate.

**No net.exe / net1.exe processes:** This technique uses `New-LocalUser`, a PowerShell cmdlet that calls the SAM API directly, rather than spawning the net command-line tool. Detections that rely on `net user` command lines will not fire on this variant.

**No Security EID 4624/4625:** The account was not used for logon during the capture window.

**No Sysmon EID 13 (Registry Value Set):** The SAM writes underlying account creation were not captured; Sysmon's include-mode ProcessCreate filter and the lack of specific SAM key targeting mean these are absent.

## Assessment

The trailing-space account name is clearly visible in both the Sysmon EID 1 command line and the PowerShell EID 4104 script block content. Any detection that captures and preserves full command-line strings, including trailing whitespace, can recover the exact account name. The risk is in detections that normalize or trim whitespace before comparison, or that alert only on `New-LocalUser -Name "Administrator"` as an exact match.

The absence of account management events means defenders relying solely on the Security log for user creation visibility will miss this event entirely. PowerShell script block logging provides the most useful signal here, since `net user` is not involved and Sysmon process creates would catch the parent PowerShell invocation but require careful examination of the full `-Name` parameter value.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script block containing `New-LocalUser` with a `-Name` value that, when trimmed, equals a privileged built-in account name (`Administrator`, `Guest`, etc.). Detection logic must preserve trailing whitespace to catch this class of evasion.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `New-LocalUser` executed under SYSTEM in a non-interactive session from `C:\Windows\TEMP\`.
- **PowerShell EID 4103:** `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` under SYSTEM; this is a consistent pattern across all ART test framework invocations and may serve as a pivot point.
- **Behavioral:** `New-LocalUser` invocations that create accounts with names differing from existing accounts by only whitespace — requires a lookup against existing account names at detection time.
- **Gap:** No Security account management events are present. Environments that rely exclusively on 4720 for new account alerts will have no visibility into this event.
