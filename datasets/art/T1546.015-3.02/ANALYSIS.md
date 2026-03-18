# T1546.015-3: Component Object Model Hijacking — COM Hijacking with RunDLL32 (Local Server Switch)

## Technique Context

T1546.015 (Component Object Model Hijacking) abuses Windows' COM object resolution to redirect application behavior to attacker-controlled code. COM consumers look up CLSID registrations in HKCU before HKLM, so a user-writable entry under `HKCU\Software\Classes\CLSID\` can shadow a system-wide registration. This test exercises the `-localserver` variant: rather than loading a DLL in-process via `InprocServer32`, the attacker registers an in-process COM server under a CLSID in the user hive and invokes it via `rundll32.exe -localserver <CLSID>`. The `-localserver` flag causes `rundll32.exe` to register and activate the COM object as an out-of-process local server host. This can bypass application allowlisting policies that permit `rundll32.exe` while blocking arbitrary DLL loads.

The test targets CLSID `{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}` (MSAA AccPropServices) and registers the ART test DLL `T1546.015_calc.dll` as its `InprocServer32`. Since the code runs as SYSTEM, the user hive in play is `HKU\.DEFAULT` rather than a named user's hive.

In the defended variant, the same artifact chain appeared — Windows Defender did not block this test in either configuration.

## What This Dataset Contains

The dataset spans approximately 7 seconds (2026-03-17 17:07:10–17:07:17 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (41 events — Event IDs 1, 3, 7, 10, 11, 17):**

Sysmon EID 1 (ProcessCreate, 5 events) records:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` with the full setup command:
   ```
   "powershell.exe" & {New-Item -Path 'HKCU:\SOFTWARE\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}' -Value 'MSAA AccPropServices'
   New-Item -Path 'HKCU:\SOFTWARE\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32' -Value "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1546.015_calc.dll"
   New-ItemProperty -Path '...\InprocServer32' -Name 'ThreadingModel' -Value 'Both' -PropertyType "String"
   Start-Process -FilePath "C:\Windows\System32\RUNDLL32.EXE" -ArgumentList '-localserver {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}'}
   ```
   Tagged `technique_id=T1083` (File and Directory Discovery) by the sysmon-modular rule matching on `New-Item` in the command line.

The PowerShell command line fully discloses the registration target and DLL path. The `rundll32.exe` child process is spawned via `Start-Process` from within this PowerShell instance.

Sysmon EID 3 (NetworkConnection) records an outbound TCP connection from `MsMpEng.exe` (Windows Defender, even with real-time protection disabled, still makes cloud-lookup connections). This is environmental noise, not technique-specific.

Sysmon EID 11 (FileCreate) records PowerShell writing startup profile data to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`. This is a standard artifact of non-interactive PowerShell execution.

Sysmon EID 10 (ProcessAccess, 4 events) records `powershell.exe` accessing `whoami.exe` and a child `powershell.exe` with `GrantedAccess: 0x1FFFFF`, tagged `technique_id=T1055.001` — standard ART test framework behavior.

Sysmon EID 7 (ImageLoad, 26 events) records .NET runtime DLLs, PowerShell automation DLLs (tagged `T1059.001`), and Defender DLLs (`MpOAV.dll`, `MpClient.dll`, tagged `T1574.002`) loading into the two PowerShell instances.

Sysmon EID 17 (PipeCreate, 3 events) records named pipes for the two PowerShell instances and the `rundll32.exe` activation.

**Note on registry artifacts:** The EID breakdown shows no Sysmon EID 13 (RegistrySetValue) events. The COM key writes were performed by `powershell.exe` using `New-Item` and `New-ItemProperty`, and the sysmon-modular include configuration did not capture writes to `HKU\.DEFAULT\Software\Classes\CLSID\{B5F8350B-...}` in this ruleset. The registry artifacts are inferred from the PowerShell command line rather than directly observed via EID 13.

**Security (5 events — Event ID 4688):**

Five process creation events covering `whoami.exe`, the setup `powershell.exe`, and cleanup process invocations, all under `NT AUTHORITY\SYSTEM`. The `powershell.exe` entry carries the full command line establishing the COM hijack.

**PowerShell (127 events — Event IDs 4103, 4104):**

EID 4104 (ScriptBlock Logging, 123 events) records the full test and cleanup scripts. The outer ART test framework wrapper, the COM registration block, and the `Start-Process` for `rundll32.exe` all appear in ScriptBlock logging. This is the most verbose channel and provides redundant coverage of the setup steps.

## What This Dataset Does Not Contain

- **No Sysmon EID 13 (RegistrySetValue):** The COM hijack registry writes are not directly captured as registry events. You can reconstruct what was written from the EID 1 / EID 4104 command lines, but the dataset lacks the direct registry telemetry that would confirm the persistence artifact was actually created in the hive.
- **No rundll32.exe EID 1:** The `rundll32.exe -localserver` invocation is spawned by `Start-Process` inside PowerShell and appears in the PowerShell ScriptBlock log but is not captured as a Sysmon EID 1 ProcessCreate in the available samples. It is present in the process tree implied by the EID 10 access events.
- **No DLL load artifacts:** The test DLL (`T1546.015_calc.dll`) activation would produce Sysmon EID 7 events for the DLL itself loading into `rundll32.exe`. Those events are not in the samples provided, though the EID 7 pool (26 events) may contain them.
- **No actual payload execution confirmation:** `T1546.015_calc.dll` launches `calc.exe` as its demonstration payload. A `calc.exe` process creation is not confirmed in the available event samples.

## Assessment

This dataset captures the registration half of the COM hijacking technique clearly: the full `InprocServer32` path, CLSID, and DLL path are visible in both Sysmon EID 1 and Security EID 4688. The invocation via `rundll32.exe -localserver` is documented in the PowerShell command line. The absence of direct EID 13 registry confirmation is the primary gap — analysts relying solely on registry-based detections would miss the persistence write and need to pivot to process and script telemetry.

The undefended dataset (41 Sysmon events) is slightly smaller than the defended variant (50 Sysmon events), likely because Defender's presence generates additional EID 7 DLL load activity even when real-time protection is enabled but protection is ultimately not triggered.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `New-Item` targeting `HKCU:\SOFTWARE\Classes\CLSID\` combined with a path to a non-system DLL in the `AtomicRedTeam\ExternalPayloads\` directory. The CLSID and DLL path in a single command are a strong composite indicator.
- **Sysmon EID 1 / PowerShell EID 4104:** `Start-Process rundll32.exe` with `-localserver` and a CLSID argument appearing in the same script block as `InprocServer32` registration. The `-localserver` flag on `rundll32.exe` with a CLSID argument (rather than a `DllName,EntryPoint` argument) is an unusual but documented attack pattern.
- **Sysmon EID 7:** DLL loads into `rundll32.exe` from non-standard paths (e.g., `C:\AtomicRedTeam\ExternalPayloads\`) would be highly anomalous.
- **PowerShell EID 4104:** The full registration script block, including the explicit `InprocServer32` path pointing to an external DLL, is logged verbatim and provides a high-fidelity record suitable for string or regex matching.
