# T1562.001-35: Disable or Modify Tools — PowerShell

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) covers registry modifications that alter security-relevant system behavior. This test replicates the LockBit Black autologon registry configuration technique using PowerShell's `New-ItemProperty` cmdlet, paralleling the `cmd.exe`/`reg.exe` variant in test 33. Configuring automatic logon via the Winlogon policy key allows ransomware to survive a forced reboot and resume execution without user interaction. The PowerShell variant is functionally equivalent but leaves a different telemetry profile: no `cmd.exe` or `reg.exe` child processes are created, and the full configuration — including credential values — appears directly in the PowerShell script block.

## What This Dataset Contains

The dataset captures 5 seconds of telemetry from ACME-WS02 during the PowerShell-native autologon configuration test.

**Security 4688 — Process creation with full PowerShell command:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -PropertyType DWord -Value 1 -Force
New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -PropertyType String -Value Administrator -Force
New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName ...
New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword ...}
```

**PowerShell 4104 — Script block captures the four `New-ItemProperty` calls:**
All four registry values appear in the script block: `AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`, and `DefaultPassword` with their values.

**Sysmon EID 1 — Two process creates:** `whoami.exe` and the child `powershell.exe` executing the `New-ItemProperty` sequence.

**Security 4689 — Process exits:** All processes exit with `0x0`. `WmiPrvSE.exe` appeared as a 4689 exit event, indicating ambient WMI activity in the background.

**Sysmon EID 7 — Image loads:** Standard PowerShell and Defender DLLs.

**Sysmon EID 10 — Process access:** ART test framework overhead (PowerShell accessing child processes).

**PowerShell 4103 — Module logging:** Only `Set-ExecutionPolicy -Bypass` appears (test framework boilerplate).

## What This Dataset Does Not Contain (and Why)

**`reg.exe` or `cmd.exe` process creates** — The PowerShell-native `New-ItemProperty` cmdlet writes registry values directly without spawning child processes. Detections based solely on `reg.exe` command line monitoring will miss this variant.

**Sysmon EID 13 (registry write)** — The Winlogon policy path is not in the sysmon-modular EID 13 include rules, so the writes are not captured as Sysmon registry events.

**Defender block** — The HKLM Winlogon policy key is writable by SYSTEM. Tamper Protection does not cover this path, and all four `New-ItemProperty` calls succeeded.

**Logon events showing autologon** — The test does not trigger a reboot, so no automatic logon session appears in the data.

**Credential masking in script blocks** — The plaintext `DefaultPassword` value appears in the PowerShell 4104 script block. PowerShell script block logging does not mask parameter values, including credential strings.

## Assessment

This is a **successful execution** dataset and the PowerShell equivalent of test 33. The credential values (`DefaultPassword`) appear in the PowerShell 4104 script block in cleartext, making this dataset directly comparable to test 33 where they appeared in `reg.exe` command lines (Security 4688). From a detection perspective, this variant is slightly harder to catch via process-creation monitoring alone because no child processes are spawned. PowerShell 4104 and Security 4688 (parent command line) are the primary detection surfaces. The `WmiPrvSE.exe` exit event in Security 4689 is ambient background WMI activity, not related to this test.

## Detection Opportunities Present in This Data

- **`New-ItemProperty` writing `DefaultPassword` to Winlogon key** (PowerShell 4104): The cleartext password value in the script block is a high-confidence indicator. `DefaultPassword` as a value name in any PowerShell registry call is suspicious.
- **`HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon` in PowerShell scripts**: This path is directly associated with LockBit Black. Combined with `AutoAdminLogon` or `DefaultPassword`, it is a strong detection signal.
- **Multi-value configuration pattern**: Four consecutive `New-ItemProperty` calls to the same Winlogon base path in a single script block is characteristic of the LockBit autologon setup sequence.
- **Cross-test comparison with test 33**: A detection rule must cover both the `reg.exe` invocation pattern (test 33) and the `New-ItemProperty` pattern (this test) to fully address both execution variants.
- **Cleartext credential monitoring**: PowerShell 4104 events containing `DefaultPassword` with a non-empty string value should trigger credential-exposure alerts in addition to the technique-specific detection.
