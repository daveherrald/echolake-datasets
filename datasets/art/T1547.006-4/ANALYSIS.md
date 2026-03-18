# T1547.006-4: Kernel Modules and Extensions — Kernel Modules and Extensions - Snake Malware Kernel Driver Comadmin

## Technique Context

T1547.006 (Kernel Modules and Extensions) covers adversary use of kernel drivers for persistence and privilege escalation. On Windows, this typically involves installing a malicious driver as a service or placing driver files in locations where they are loaded by the kernel. This specific test emulates an artifact associated with Snake malware (Turla group), which used a file named `comadmin.dat` placed in `C:\Windows\System32\Com\` as part of its kernel driver persistence mechanism. The test does not load an actual kernel driver — it writes a file with random bytes to the expected path to simulate the file-drop stage of this technique.

## What This Dataset Contains

The test creates a file at `C:\Windows\System32\Com\comadmin.dat` containing 4096 random bytes, simulating the Snake malware kernel driver artifact. A Sysmon EID 11 (FileCreate) records the creation with the rule tag `technique_id=T1574.010,technique_name=Services File Permissions Weakness` (the sysmon-modular config matches this path due to its location in a services-writable system directory):

```
File created:
  RuleName: technique_id=T1574.010,technique_name=Services File Permissions Weakness
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetFilename: C:\Windows\System32\Com\comadmin.dat
```

Note that the sysmon rule fires with a T1574.010 tag rather than T1547.006 — the ruleset does not have a specific rule for this path but matches it via a general services directory pattern.

The PowerShell EID 4104 script block is captured in full:

```powershell
$examplePath = Join-Path $env:windir "system32\Com";
if (-not (Test-Path $examplePath)) { New-Item -ItemType Directory -Path $examplePath | Out-Null };
$exampleName = "comadmin.dat";
$exampleFullPath = Join-Path $examplePath $exampleName;
$randomBytes = New-Object Byte[] 0x1000;
(New-Object Random).NextBytes($randomBytes);
[System.IO.File]::WriteAllBytes($exampleFullPath, $randomBytes)
```

Sysmon event counts: 27 events across EID 1 (3), EID 7 (17), EID 10 (2), EID 11 (3), EID 17 (2). The EID 1 entries capture `whoami.exe` (T1033) and two PowerShell processes (T1083). No EID 13 registry events are present — this technique variant is purely file-based.

Security events: 10 events (4688 × 2, 4689 × 7, 4703 × 1). One Security 4688 captures the PowerShell process with the full `system32\Com` path visible in the command line.

## What This Dataset Does Not Contain

**No kernel driver loading occurs.** The test writes a random-byte file — it does not register or load a driver service. No Sysmon EID 6 (DriverLoad) is generated.

**No sc.exe or service creation** is present. The Snake kernel driver persistence mechanism involves a service registration step that is not emulated in this test — the test focuses only on the file artifact.

**No registry modifications** — the service registration for a kernel driver would normally create entries under `HKLM\SYSTEM\CurrentControlSet\Services`, but this test does not perform that step.

**Windows Defender did not flag the file write** — the file contains random bytes with no known signature. A real kernel driver would likely be detected by Defender's driver signing and behavior enforcement.

**Sysmon EID 13 is absent** because no registry modifications occur in this test.

## Assessment

The test ran to completion. The file drop to `C:\Windows\System32\Com\comadmin.dat` is confirmed by Sysmon EID 11 and the PowerShell script block. The dataset represents the file-drop phase of the Snake malware kernel driver technique, without the service registration or driver loading that would complete the persistence chain. The attribution to T1574.010 in the Sysmon rule tag rather than T1547.006 reflects a ruleset coverage gap for this specific indicator.

## Detection Opportunities Present in This Data

- **Sysmon EID 11**: File creation at `C:\Windows\System32\Com\comadmin.dat` is a published Snake malware IoC. A targeted rule on this exact path is high-fidelity.
- **PowerShell EID 4104**: The script block shows the `system32\Com` path construction and use of `[System.IO.File]::WriteAllBytes()` — an unusual method for writing to a protected system directory.
- **Security EID 4688**: The PowerShell command line contains the `system32\Com` path, offering detection from process creation logs.
- **General rule**: Any process creating files in `C:\Windows\System32\Com\` is rare and warrants investigation. This path is not used by legitimate Windows components for file writes.
- The sysmon-modular rule fires a T1574.010 tag on this file path — this is technically a mislabel but still produces an alert that would surface the event.
