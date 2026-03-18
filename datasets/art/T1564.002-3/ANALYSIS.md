# T1564.002-3: Hidden Users — Create Hidden User in Registry

## Technique Context

MITRE ATT&CK T1564.002 (Hidden Users) covers techniques for creating local user accounts that are suppressed from the Windows login screen and standard user enumeration tools. This test combines two actions:

1. Creates a local user account named `AtomicOperator$` using `net user`
2. Adds a registry entry to hide it from the Windows login screen:
   ```
   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist\AtomicOperator$ = DWORD 0
   ```

The `SpecialAccounts\Userlist` registry key is the standard mechanism Windows uses to hide accounts from the graphical login picker. Any account with a value of `0` under this key is excluded from the Welcome screen and Fast User Switching UI. This does not prevent the account from being used; it can still be used for network logons, `runas`, and remote access. The technique is commonly used to establish a persistent backdoor account that is invisible during casual inspection.

The dollar-sign suffix on the account name (`AtomicOperator$`) combines the registry-based hiding with the naming obfuscation technique from T1564-2, making the account harder to find via both GUI inspection and `net user` enumeration.

## What This Dataset Contains

The dataset spans approximately 4 seconds (14:21:59–14:22:03 UTC) and is the most compact dataset in this collection.

**Process execution chain (Sysmon EID 1):**

The ART test framework issued a compound command through cmd.exe:

```
"cmd.exe" /c NET USER AtomicOperator$ At0micRedTeam! /ADD /expires:never  & REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0
```

Four child processes were spawned:
- `net.exe` → `NET  USER AtomicOperator$ At0micRedTeam! /ADD /expires:never`
- `net1.exe` → `C:\Windows\system32\net1  USER AtomicOperator$ At0micRedTeam! /ADD /expires:never`
- `reg.exe` → `REG  ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0`

All four are captured as Sysmon EID 1 with full command lines. The account name and password are visible in the net.exe/net1.exe command lines.

**Sysmon EID 13 (Registry Value Set):** The reg.exe execution generated a registry write event:

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist\AtomicOperator$
Details: DWORD (0x00000000)
RuleName: technique_id=T1547.004,technique_name=Winlogon Helper DLL
```

The RuleName `T1547.004` (Winlogon Helper DLL) is a sysmon-modular label from a rule monitoring the Winlogon key broadly. While technically a mislabeled technique (T1564.002 is more accurate), the event is captured and the target path and value are recorded precisely.

**Security EID 4688:** Process creates for whoami.exe, cmd.exe, net.exe, net1.exe, and reg.exe, all as SYSTEM.

**Security EID 4703:** Token right adjustment.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Bypass` test framework invocation.

## What This Dataset Does Not Contain (and Why)

**No account management events (4720, 4726):** Account management auditing is disabled (`account_management: none`). The account creation — the most direct evidence of a new user — generates no event in the Security log. This is the same limitation observed in T1564-2 and T1564-3.

**No Security EID 4657 (Registry Object Modified):** Object access auditing is disabled.

**No Sysmon EID 12 (Registry Key Create):** The `SpecialAccounts\Userlist` key may have already existed; the Sysmon EID 13 captured the value write, but no key creation event is present.

**No logon events for the new account:** The account was not used for authentication during the capture window.

## Assessment

This dataset is significant because it captures both the account creation command (net.exe) and the registry hiding step (reg.exe / Sysmon EID 13) in the same window. The Sysmon EID 13 entry for `HKLM\...\Winlogon\SpecialAccounts\Userlist\AtomicOperator$` with `DWORD (0x00000000)` is a high-confidence indicator that appears independently of the process execution chain.

The absence of account management events (4720) means that the account creation itself is not independently confirmed in the Security log — only the tools used to create it are logged. This is a meaningful coverage gap for environments that rely on Security log account management events for user creation detection.

The dollar-sign suffix in the account name is visible in all five relevant command lines (cmd.exe, net.exe, net1.exe, reg.exe invocation, and the Sysmon EID 13 TargetObject), making it a reliable search term.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 (RuleName: T1547.004):** Registry write to `HKLM\...\Winlogon\SpecialAccounts\Userlist\<username>` with value `0`. This is the canonical indicator for login-screen user hiding and should be treated as high severity regardless of the creating process.
- **Sysmon EID 1 / Security EID 4688:** `reg.exe` command line referencing `Winlogon\SpecialAccounts\Userlist` — the full key path is present in the command argument.
- **Sysmon EID 1 / Security EID 4688:** `net.exe` or `net1.exe` command line containing a dollar-sign-suffixed username with `/ADD` — combining account creation with an obfuscated name.
- **Correlation:** `net user /ADD` followed within the same second by a `reg add SpecialAccounts\Userlist` write for the same account name is a paired detection opportunity. Either event alone is suspicious; together they confirm deliberate hidden account establishment.
- **Gap:** No account management events (4720) are present. Detection that depends solely on Security log account creation events would have no visibility into this execution. The Sysmon EID 13 and the process command lines are the primary evidence sources.
