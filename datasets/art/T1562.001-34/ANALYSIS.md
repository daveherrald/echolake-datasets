# T1562.001-34: Disable or Modify Tools — PowerShell

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes registry modifications that suppress Windows security and privacy components. This test replicates the LockBit Black `DisablePrivacyExperience` technique using PowerShell's `New-ItemProperty` cmdlet rather than `cmd.exe` and `reg.exe`. The OOBE privacy settings page controls user-facing controls for diagnostic data and telemetry. Disabling it is a pre-encryption housekeeping step used by LockBit to reduce potential interference from post-reboot first-run experiences. This PowerShell variant (test 34) parallels the `cmd.exe` variant (test 32), allowing comparison of telemetry produced by different execution vectors for the same registry modification.

## What This Dataset Contains

The dataset captures 5 seconds of telemetry from ACME-WS02 during the PowerShell-native registry modification test.

**Security 4688 — Process creation with the PowerShell command as the command line:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\OOBE" -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force}
```

**PowerShell 4104 — Script block logging captures the `New-ItemProperty` invocation verbatim:**
```
& {New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\OOBE" -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force}
```

**Sysmon EID 1 — Two process creates:** `whoami.exe` (ART identity check) and the child `powershell.exe` executing the `New-ItemProperty` command.

**Sysmon EID 7 — Image loads:** PowerShell runtime and Defender DLLs. The .NET CLR loads are consistent with PowerShell-native registry operations.

**Sysmon EID 10 — Process access:** PowerShell parent accessing child processes with full access (`0x1FFFFF`), standard ART test framework overhead.

**Security 4689 — Process exits:** All processes exit with `0x0`. The child `powershell.exe` running `New-ItemProperty` exited cleanly, consistent with a successful registry write.

**PowerShell 4103 — Module logging:** Only the test framework `Set-ExecutionPolicy -Bypass` invocation appears; `New-ItemProperty` does not generate module pipeline output in this configuration.

## What This Dataset Does Not Contain (and Why)

**`reg.exe` or `cmd.exe` process creates** — This is the PowerShell-native variant. The registry modification is performed entirely within the PowerShell process using the .NET registry API. No child processes are spawned for the modification itself, contrasting with test 32.

**Sysmon EID 13 (registry write)** — The OOBE policy registry path is not in the sysmon-modular EID 13 include rules, so the write is not captured as a Sysmon registry event. The PowerShell 4104 script block and Security 4688 command line provide the equivalent evidence.

**Defender block or error** — `New-ItemProperty` writing to an HKCU policy path is not subject to Defender Tamper Protection. No 4100 errors appear and the operation succeeded.

**WMI or COM events** — `New-ItemProperty` using the PowerShell registry provider does not invoke WMI. No WMI activity is expected.

## Assessment

This is a **successful execution** dataset and a clean comparison point for test 32 (the `cmd.exe`/`reg.exe` variant). The key differences: this test generates no child process for the registry modification (no `cmd.exe`, no `reg.exe`), and the operation is captured entirely in the PowerShell 4104 script block and Security 4688 command line. The absence of a `reg.exe` child process means detections based solely on `reg.exe` command line monitoring will miss this variant. The `New-ItemProperty` approach leaves a clean script block logging signature with the full registry path, value name, type, and data visible in plaintext. Both test 32 and test 34 succeed on the same HKCU key — demonstrating that the same outcome can be achieved through different execution vectors, each with a distinct telemetry profile.

## Detection Opportunities Present in This Data

- **`New-ItemProperty` with `DisablePrivacyExperience`** (PowerShell 4104 / Security 4688): The cmdlet call with the specific value name is a high-confidence indicator. Both the command line (4688) and the script block (4104) capture it in full.
- **`HKCU:\Software\Policies\Microsoft\Windows\OOBE` registry path in PowerShell scripts**: This path in any PowerShell execution context — regardless of cmdlet used — is strongly associated with LockBit Black.
- **Comparison with cmd/reg variant detection**: A detection rule targeting `reg.exe` with the OOBE key path will miss this test. Coverage requires either registry auditing (Sysmon EID 13 with appropriate include rules) or PowerShell script block monitoring.
- **PowerShell 4103 showing only `Set-ExecutionPolicy`**: The consistent `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` pattern across all ART tests is boilerplate test framework overhead. It can be used to identify ART-executed tests but should not be the sole basis for an alert.
