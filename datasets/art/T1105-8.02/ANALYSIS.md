# T1105-8: Ingress Tool Transfer — certutil download (verifyctl)

## Technique Context

T1105 (Ingress Tool Transfer) encompasses all mechanisms used to bring files into a compromised environment. Certutil.exe's `verifyctl` subcommand—designed to verify certificate trust lists—also accepts a URL and downloads the content as part of its verification process. The `-split` and `-f` flags force downloading and splitting the output, making this a functional alternative to the more commonly known `-urlcache` variant (T1105-7).

The `verifyctl` approach differs from `urlcache` in two ways relevant to defenders: first, it creates a date-named working directory as a side effect of its operation, and second, the downloaded file is placed in that new directory rather than the current working directory. This directory creation is a distinctive behavioral artifact unique to `verifyctl`-based downloads.

The full command executed here is: `certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt`, run from a date-named subdirectory.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled.

**Process Chain (Security EID 4688):**

The ART test framework PowerShell (PID 0x14f8 / 5368) spawns a child PowerShell (PID 0x18ac / 6284) with the full attack command:

```
"powershell.exe" & {$datePath = "certutil-$(Get-Date -format yyyy_MM_dd)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt}
```

This command creates a directory named `certutil-<date>`, changes into it, then runs certutil from within that directory. The directory creation, location change, and certutil execution all happen within the child PowerShell process, not as separate spawned processes visible in the Security channel.

**Sysmon CreateRemoteThread (EID 8):**

PowerShell (PID 5368) targets process PID 6316 (`<unknown process>`) with a remote thread at `StartAddress: 0x00007FF77E8753A0`. This is the same ART test framework child-process management artifact seen in T1105-7—Sysmon classifies it as `technique_id=T1055` (Process Injection), but this reflects the .NET process management internals rather than actual injection. The unknown target process corresponds to the certutil.exe instance before its image is fully mapped.

**File Creation by Windows Defender (Sysmon EID 11):**

`MsMpEng.exe` (PID 5384, `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe`) creates `C:\Windows\Temp\01dcb40cbb39c970` at 23:46:08.800. Even with Defender disabled via policy, the MsMpEng.exe process continues to run and performs periodic internal operations. This file write in `C:\Windows\Temp\` is a Defender housekeeping artifact, not a technique-generated artifact. It will appear consistently in undefended datasets where MsMpEng.exe remains resident.

**Process Access (Sysmon EID 10):**

PowerShell (PID 5368) accesses `whoami.exe` (PID 2284) with `GrantedAccess: 0x1FFFFF`—the ART test framework pattern.

**Image Loads (Sysmon EID 7):**

Nine DLL loads for the test framework PowerShell (PID 5368): standard .NET runtime components.

**PowerShell Script Block Logging (EID 4104/4100/4103):**

39 events: 36 EID 4104 blocks, 2 EID 4100 error starts, 1 EID 4103 pipeline execution. The 4100/4103 pattern mirrors T1105-7 and reflects the PowerShell execution model used to pass the certutil command through the inline script block.

**Application Log (EID 15):**

Windows Security Center records `SECURITY_PRODUCT_STATE_ON` for Windows Defender—consistent with the test framework test sequence re-enabling Defender state between tests.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) or EID 22 (DNS query) captures the certutil network activity. The certutil download occurs inside the child PowerShell process as a shell command, and certutil's WinHTTP-based network stack does not generate Sysmon network events in this configuration.

The created directory (`certutil-<date>`) and the downloaded `Atomic-license.txt` do not appear as EID 11 file creation events in the sample set. The date-named directory creation via `New-Item` and the subsequent certutil write occurred in the child PowerShell, and those specific file writes were not captured in the sampled events.

Certutil.exe itself does not appear as an EID 1 process create in the Sysmon samples—certutil runs within the PowerShell script block context and may be executed via `Invoke-Expression` or direct string execution rather than a spawned subprocess, depending on how the ART module invokes it. The Security channel shows the child PowerShell command line, not certutil directly.

## Assessment

The undefended dataset for this certutil verifyctl test is thinner than T1105-7 (certutil urlcache) in terms of raw events: 39 PowerShell events versus 55, and 16 Sysmon events versus 21. The critical evidence—the full certutil verifyctl command line—appears in Security 4688 on the child PowerShell process creation event. The EID 8 CreateRemoteThread artifact is present as in T1105-7.

The distinctive behavioral difference from T1105-7 is the directory creation step: `New-Item -Path certutil-<date> -ItemType Directory` before the download. This directory creation is a reliable behavioral signature for the verifyctl download pattern. In the defended variant (event counts: sysmon 16, security 3, powershell 36), the same structural pattern holds but with Defender's scan-related process spawning adding events to the security channel.

The MsMpEng.exe file creation in `C:\Windows\Temp\` is worth noting as background activity present in all undefended datasets—it is a consistent MsMpEng housekeeping artifact that investigators should recognize and exclude from technique-related analysis.

## Detection Opportunities Present in This Data

**Certutil -verifyctl in command line (EID 4688):** The string `certutil -verifyctl -split -f <https-url>` is a high-fidelity indicator. The `verifyctl` subcommand serves no legitimate administrative purpose that requires an external HTTP URL as its argument.

**PowerShell script block with directory creation preceding certutil (EID 4104):** The pattern of creating a dated directory followed by running certutil from within it is a behavioral signature unique to the verifyctl download pattern. If script block logging is enabled and captures the `New-Item ... -ItemType Directory` plus certutil sequence in adjacent EID 4104 events, the combination is definitive.

**Certutil spawned from PowerShell (EID 1, if captured):** In environments where certutil does appear as a child process of PowerShell (rather than running inline), the parent-child relationship `powershell.exe → certutil.exe` with a URL argument is a direct indicator.

**MsMpEng.exe file write in C:\Windows\Temp\ (EID 11):** As noted, this is background Defender activity and should not be attributed to the technique. Recognizing this pattern prevents false-positive alerting on the EID 11 event in this dataset.
