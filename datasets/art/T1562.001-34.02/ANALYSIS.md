# T1562.001-34: Disable or Modify Tools — LockBit Black - Disable Privacy Settings Experience Using Registry (PowerShell)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes registry
modifications that suppress Windows security and privacy components. This test replicates
the LockBit Black `DisablePrivacyExperience` technique using PowerShell's
`New-ItemProperty` cmdlet rather than `cmd.exe` and `reg.exe`. The OOBE privacy settings
page controls user-facing controls for diagnostic data and telemetry. Disabling it is a
pre-encryption housekeeping step used by LockBit to reduce potential interference from
post-reboot first-run experiences.

This is the PowerShell-native variant. The `cmd.exe` + `reg.exe` variant is test 32.
Comparing the two datasets illustrates how the same registry modification leaves different
telemetry footprints depending on execution vector — a key consideration when building
multi-vector detections.

In this **undefended** dataset, Defender is disabled. The registry write succeeds.

## What This Dataset Contains

The dataset captures 53 events across two channels (50 PowerShell, 3 Security) spanning
approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Three process creation events.** The attack chain here is shorter
than the cmd.exe variant because no `cmd.exe` intermediate process is needed:

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. `"powershell.exe" & {New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\OOBE" -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force}` (attack)
3. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)

The full key path (`HKCU:\Software\Policies\Microsoft\Windows\OOBE`), value name
(`DisablePrivacyExperience`), type (`DWord`), and value (`1`) are all in the 4688 command
line of the child `powershell.exe`. No `reg.exe` process is spawned.

**PowerShell EID 4104 — 49 script block events.** Two substantive blocks capture the
attack command:

```powershell
& {New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\OOBE" -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force}
```

And the inner block:

```powershell
{New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\OOBE" -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force}
```

These two events represent the outer `& {}` invocation and the inner block text — the same
script block logged from two perspectives by the PowerShell engine. This is the key
differentiator from the cmd.exe variant: the registry modification command appears in 4104
in addition to the 4688 command line.

The cleanup block is also present:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 34 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

**PowerShell EID 4103 — One module pipeline event** for the `Set-ExecutionPolicy` test framework
call.

**No EID 4100 error events.** `New-ItemProperty` completed successfully.

## What This Dataset Does Not Contain

**No `cmd.exe` or `reg.exe` process creation events.** This is the PowerShell-native
variant. The registry modification is performed entirely within the PowerShell process using
the .NET registry API (`Microsoft.Win32.RegistryKey`). No child processes are spawned for
the modification itself. This contrasts directly with test 32, where `cmd.exe` and `reg.exe`
each appear as separate 4688 events.

**No Sysmon events.** Sysmon data is not bundled. The defended dataset captures Sysmon EID 1
(process creates), EID 7 (image loads), and EID 10 (process access) for this test.

**No Sysmon EID 13 (registry value set).** The HKCU OOBE policy path is not in the
sysmon-modular include rules, consistent with the cmd.exe variant. The PowerShell 4104
script block and 4688 command line provide equivalent evidence.

**No cleanup events visible in the Security channel.** The ART cleanup (removing the
`DisablePrivacyExperience` value) runs via the `Invoke-AtomicTest -Cleanup` block, which
would invoke `Remove-ItemProperty` internally. No corresponding 4688 events for the cleanup
appear in the three Security events captured — the cleanup's process creates either occurred
outside the time window or were not captured in the sampled events.

## Assessment

This dataset demonstrates the PowerShell-native path for the LockBit Black
`DisablePrivacyExperience` technique. The modification succeeds silently, as confirmed by
the absence of 4100 errors and the clean exit of the child `powershell.exe`.

The direct comparison with test 32 is this dataset's primary analytical value. Test 32
produces 6 Security 4688 events (cmd.exe + four reg.exe calls + whoami twice) with no
matching 4104 content for the modification commands. Test 34 produces 3 Security 4688 events
(no cmd.exe or reg.exe) but adds the `New-ItemProperty` command in two 4104 script blocks.
A detection relying solely on `reg.exe` command line monitoring would catch test 32 and miss
test 34. A detection relying solely on 4104 script block content would catch test 34 and
miss test 32.

Both variants are functionally equivalent in their outcome and both appear as SYSTEM-context
process creates in 4688.

## Detection Opportunities Present in This Data

**Security EID 4688 — `New-ItemProperty` with `HKCU:\Software\Policies\Microsoft\Windows\
OOBE` and `DisablePrivacyExperience` in the PowerShell command line.** The full command
including the key path, value name, and value appears in the child PowerShell process's
command line in the 4688 event.

**PowerShell EID 4104 — `New-ItemProperty` targeting the OOBE policy key with
`DisablePrivacyExperience -Value 1`.** Script block logging captures the command verbatim.
Unlike the cmd.exe variant, this path provides the full command in 4104 as well as 4688,
giving two independent log sources for the same indicator.

**Behavioral comparison: `reg.exe` absence as a distinguisher.** Defenders who have
observed this technique in the wild via `reg.exe` (as in LockBit Black's original behavior)
should be aware that the PowerShell-native variant produces an identical registry outcome
with no `reg.exe` or `cmd.exe` child processes. Coverage across both execution vectors
requires monitoring both process command lines and PowerShell script blocks.

**SYSTEM context writing to HKCU policy.** As with test 32, a SYSTEM-privileged process
modifying `HKCU\Software\Policies\Microsoft\Windows\OOBE` is not a normal administrative
pattern. The HKCU policy hive is per-user and is typically managed by Group Policy
infrastructure, not by SYSTEM-level PowerShell scripts.
