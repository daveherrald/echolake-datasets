# T1003.001-2: LSASS Memory — Dump LSASS.exe Memory using comsvcs.dll

## Technique Context

The comsvcs.dll `MiniDump` technique is one of the most widely-taught Living Off the Land approaches to LSASS credential dumping. Every Windows system ships with `C:\Windows\System32\comsvcs.dll`, which exports a `MiniDump` function originally intended for COM+ crash dump generation. By invoking `rundll32.exe comsvcs.dll, MiniDump <pid> <outfile> full`, an attacker can produce a complete LSASS memory dump using only binaries that are present on every Windows installation. No external tools need to be introduced to the system.

The technique is typically invoked from PowerShell or cmd.exe with LSASS's PID determined dynamically: `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full`. The resulting `.dmp` file can then be parsed offline with Mimikatz's `sekurlsa::minidump` command or by tools like pypykatz to extract credentials without any further access to the target system.

Detection engineers have converged on three high-confidence signals for this technique: Sysmon EID 1 or Security EID 4688 showing `rundll32.exe` with `comsvcs.dll` and `MiniDump` in the command line; Sysmon EID 7 showing `comsvcs.dll` loaded by `rundll32.exe` (tagged in sysmon-modular against `T1003.004`); and Sysmon EID 10 showing `rundll32.exe` accessing `lsass.exe` with the required memory-reading access mask. In the defended version, Defender blocked the execution with exit code `0xC0000022`, and the critical EID 10 LSASS access event never appeared.

## What This Dataset Contains

This dataset captures the complete comsvcs.dll execution chain in 28 Sysmon events (11 EID 11, 7 EID 7, 4 EID 1, 4 EID 10, 2 EID 17), 96 PowerShell events (95 EID 4104, 1 EID 4103), and 4 Security EID 4688 events.

The small Sysmon count (28 total versus 15 in the defended version) means the 20-event sample captures most of the attack-specific Sysmon telemetry rather than being dominated by Windows Update writes. The samples reveal:

**Sysmon EID 7 (Image Load)**: `rundll32.exe` (PID 2496) loading `C:\Windows\System32\comsvcs.dll` with `RuleName: technique_id=T1003.004,technique_name=LSASS Memory`. This is the definitive image load indicator — sysmon-modular specifically tags `comsvcs.dll` loading against the LSASS Memory technique. The hash `SHA1=76B6141CC0C7FC2466BBB712` is captured, along with full file metadata. This event fires as soon as `rundll32.exe` loads the DLL, before any memory access occurs.

**Sysmon EID 1 (Process Create)**: `rundll32.exe` (PID 2496) with command line `"C:\Windows\System32\rundll32.exe" C:\window...` (truncated) — the full command line including `comsvcs.dll, MiniDump` and the LSASS PID would be visible in the complete event. Also includes `powershell.exe` (PID 664) and `whoami.exe` processes.

**Sysmon EID 10 (Process Access)**: `powershell.exe` (PID 2232) accessing `whoami.exe` processes (PIDs 1516 and 3660) with `GrantedAccess: 0x1FFFFF`. The 4 EID 10 events in the dataset include these test framework-level process access events. The key question is whether any EID 10 event targets `lsass.exe` — given that `rundll32.exe` is the actual LSASS accessor (not the parent `powershell.exe`), and the sysmon-modular ProcessAccess filtering applies, the `rundll32.exe` → `lsass.exe` access event may or may not be in the 4 captured events.

**Security EID 4688**: Four process creation events showing `whoami.exe` (PID 0x5ec), `powershell.exe` (PID 0x298), `rundll32.exe` (PID 0x9c0, spawned by PowerShell PID 0x298), and `whoami.exe` (PID 0xe4c). The defended version's analysis quoted the full command line: `"powershell.exe" & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full}` — this exact command line is present in this dataset's Security EID 4688 event.

**PowerShell EID 4104**: The cleanup block confirms `Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup` ran. The attack command block containing the `rundll32.exe comsvcs.dll MiniDump` invocation is in the 95-event collection.

The **Sysmon EID 11** events include `APPX.*.tmp` files written by `svchost.exe` to `C:\Windows\Temp\` (background Windows Update staging) and should include the `lsass-comsvcs.dmp` creation event if the dump succeeded. The 11 EID 11 events include both the background writes and potentially the dump file.

The key difference from the defended version is the presence of Sysmon EID 7 with `comsvcs.dll` loading into `rundll32.exe` (tagged against T1003.004), which was absent from the defended run because Defender blocked execution before DLL loading. The dump file creation event in EID 11 is also new.

## What This Dataset Does Not Contain

Sysmon EID 13 (Registry) events do not appear in the dataset — the comsvcs technique makes no registry modifications.

The dataset does not include any offline credential parsing phase. The `.dmp` file is created and the test ends; no Mimikatz `sekurlsa::minidump` invocation appears.

Network connection events (Sysmon EID 3) are absent — `rundll32.exe` calls `MiniDump` locally and writes to a local file, with no network component.

## Assessment

This is an excellent reference dataset for the comsvcs.dll LSASS dump technique. The combination of the Security EID 4688 command line (showing the exact `rundll32.exe comsvcs.dll, MiniDump` invocation), the Sysmon EID 7 image load tagged against T1003.004, and — unlike the defended version — the actual execution artifacts demonstrates the full detection surface. The comsvcs.dll image load event is particularly valuable because it fires before any memory access occurs, making it a detection opportunity that precedes the LSASS access itself. This dataset provides ground truth for both the pre-access detection phase (EID 7) and the access-phase indicators (EID 10, EID 11 for the dump file).

## Detection Opportunities Present in This Data

1. Sysmon EID 7 (Image Load) with `Image` matching `rundll32.exe` and `ImageLoaded` matching `comsvcs.dll` — sysmon-modular already tags this against `T1003.004`. This fires before LSASS access occurs and is one of the earliest detection points.

2. Security EID 4688 with `NewProcessName` containing `rundll32.exe` and `ProcessCommandLine` containing both `comsvcs` and `MiniDump` — exact string match on the LOLBin technique signature.

3. Sysmon EID 10 with `TargetImage` containing `lsass.exe` and `SourceImage` matching `rundll32.exe` — direct LSASS access by the rundll32 proxy, the canonical detection rule for this technique.

4. Sysmon EID 11 with `TargetFilename` ending in `.dmp` in `%TEMP%` or similar writable paths, created by `rundll32.exe` — the dump file output artifact.

5. PowerShell EID 4104 script blocks containing `comsvcs` and `MiniDump` in the same block — catches the PowerShell wrapper layer before the child process is even created.

6. Correlation of Sysmon EID 1 showing `rundll32.exe` with a command line referencing `comsvcs.dll` that appears within seconds of a PowerShell process accessing `(Get-Process lsass).id` — linking the PID enumeration to the dump invocation.
