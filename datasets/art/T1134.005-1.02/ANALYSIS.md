# T1134.005-1: SID-History Injection — Injection SID-History with mimikatz

## Technique Context

SID-History Injection (T1134.005) allows an attacker to add high-privilege Security Identifiers to a user account's SID-History attribute, granting that account the effective permissions of the injected SID without actually changing group membership. In Active Directory environments, this is a form of both privilege escalation and defense evasion: the attacker maintains a normal-looking account while silently holding Domain Admin or Enterprise Admin access rights. The canonical tool for this is mimikatz, which implements `privilege::debug`, `sid::patch`, and `sid::add` commands to directly modify the SID-History attribute via low-level API calls. Detection focuses on monitoring for mimikatz execution, suspicious process creation from PowerShell, and unusual modifications to LSASS or Active Directory account attributes.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures mimikatz launching and executing its full SID injection sequence from a domain-joined Windows 11 workstation (ACME-WS06.acme.local).

**Process execution chain:** Sysmon EID 1 records cmd.exe spawning from powershell.exe (PID 18104) with the complete mimikatz invocation:

```
"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe
  "privilege::debug" "sid::patch" "sid::add /sid:S-1-5-21-1004336348-1177238915-682003330-1134 /sam:$env:username" "exit"
```

Security EID 4688 independently records the same cmd.exe process creation, confirming both logging paths are capturing the execution. The `$env:username` variable would resolve at runtime to the logged-in username, making this a targeted SID injection against the current user's account.

**Pre-execution reconnaissance:** A `whoami.exe` process (Sysmon EID 1) executes immediately before the mimikatz command, confirming the identity context under which the attack runs. All processes run under `NT AUTHORITY\SYSTEM` with `IntegrityLevel: System`.

**Process access telemetry:** Sysmon EID 10 records powershell.exe (PID 18104) accessing both whoami.exe and cmd.exe with `GrantedAccess: 0x1FFFFF` — full access — indicating process monitoring or potential injection activity across all child processes.

**DLL load activity:** Sysmon EID 7 records nine DLL loads into the PowerShell process, including .NET runtime components (`mscoree.dll`, `clr.dll`, `mscoreei.dll`, `mscorlib.ni.dll`, `clrjit.dll`), the Windows Defender integration module (`MpOAV.dll`, `MpClient.dll`), and `urlmon.dll`. The Sysmon pipe creation event (EID 17) captures the PowerShell host pipe `\PSHost.134182391109263253.18104.DefaultAppDomain.powershell`.

**PowerShell test framework logging:** 108 PowerShell events (4104 and 4103) span the test window, covering the ART test framework execution context including `Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'`.

**Application channel:** EID 15 records SecurityCenter reporting `SECURITY_PRODUCT_STATE_ON` for Windows Defender — this is the Defender state notification from early in the test run, before the technique executed, reflecting the enabled-then-disabled state of defenses on this host.

Compared to the defended variant (26 Sysmon events, 10 Security events, 35 PowerShell events), this undefended dataset has fewer events overall (20 Sysmon, 4 Security, 108 PowerShell). The defended dataset included Security EID 4703 token rights adjustment events and blocked mimikatz before execution; this undefended dataset shows the process creation reaching cmd.exe successfully with the full mimikatz command visible, and relies entirely on process creation and PowerShell logging for detection rather than Defender block events.

## What This Dataset Does Not Contain

**Mimikatz.exe process creation:** No Sysmon EID 1 event appears for `mimikatz.exe` itself. The sysmon-modular configuration used here operates in include mode, capturing processes matching known-suspicious patterns; mimikatz.exe launched from an unusual path (`C:\AtomicRedTeam\...\ExternalPayloads\mimikatz\x64\`) may not match the filter rules. Sysmon did capture the cmd.exe that launched it.

**LSASS process access:** If mimikatz successfully executed `privilege::debug` and `sid::patch`, it would normally access the LSASS process — Sysmon EID 10 with `TargetImage: lsass.exe`. This is absent from the dataset.

**Active Directory modification events:** Successful SID-History injection would generate domain controller logs (EID 4765 "SID History was added to an account" or EID 4766). These would appear only on the DC, not on the workstation, and are not collected in this dataset.

**Outcome confirmation:** No event confirms whether the SID-History modification succeeded or failed. The technique may have executed and modified the account attribute without generating local workstation telemetry for the actual AD operation.

## Assessment

This dataset's primary detection value lies in the cmd.exe process creation with the full mimikatz command line. If you are hunting for SID-History injection attempts, Security EID 4688 and Sysmon EID 1 both capture the exact command `privilege::debug` and `sid::add /sid:...` arguments, including the target SID (`S-1-5-21-1004336348-1177238915-682003330-1134`). This makes the dataset useful for building and testing command-line-based detection logic even though the downstream AD manipulation is not locally visible.

The absence of mimikatz.exe itself in the Sysmon EID 1 data is an important gap for endpoint detection approaches that focus solely on process creation matching. The cmd.exe wrapper is clearly visible, but a detection that requires `Image` containing `mimikatz.exe` would miss this execution. The dataset demonstrates that PowerShell → cmd.exe → [tool] chains require detection at the cmd.exe layer or earlier.

Compared to the defended variant, this dataset is notably simpler: Defender blocking generated richer telemetry (token rights adjustment events, blocked-script PowerShell errors) that inadvertently produced more detection signals. The undefended execution is cleaner and in some ways harder to detect without process creation monitoring, since there are no block-event artifacts.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** cmd.exe spawned by powershell.exe with command line containing `mimikatz.exe` and the strings `privilege::debug`, `sid::patch`, or `sid::add` — high-fidelity indicators regardless of path obfuscation
- **Sysmon EID 10:** powershell.exe accessing child processes with `GrantedAccess: 0x1FFFFF` — broad access rights to child process objects is anomalous for normal PowerShell usage
- **Sysmon EID 7:** Windows Defender DLLs (`MpOAV.dll`, `MpClient.dll`) loading into PowerShell is not itself malicious but confirms Defender is scanning the process, useful as context in alert triage
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` remains visible in test framework telemetry and is a consistent indicator of automated ART-style execution
- **Command-line pattern:** The SID value `S-1-5-21-1004336348-1177238915-682003330-1134` is domain-specific; hunting for `sid::add` with any SID argument is a viable approach for this technique family
