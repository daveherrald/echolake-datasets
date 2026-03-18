# T1070.006-8: Timestomp — Timestomp a File Using a Custom PowerShell Module

## Technique Context

T1070.006 (Timestomp) covers adversary manipulation of NTFS file timestamps to defeat forensic timeline analysis. This test uses a purpose-built timestomping PowerShell module (`timestomp.ps1`) rather than the inline `.LastWriteTime`/`.CreationTime` property assignments seen in T1070.006-5 and T1070.006-6. A dedicated timestomping tool typically offers more comprehensive manipulation — setting all four MACE timestamps (Modified, Accessed, Changed, Born) simultaneously — and may use lower-level Windows API calls (`SetFileTime`, `NtSetInformationFile`) that are harder to detect via standard telemetry than the `.NET FileInfo` property approach.

The target file is `kxwn.lock` in the `ExternalPayloads` directory — a synthetic file with a `.lock` extension that could plausibly represent a lock file for some application. The choice of `.lock` extension suggests the module can target any arbitrary file, not just executable types.

Using a dedicated timestomping module is a more capable approach than single-property assignment: it can modify timestamps that are inaccessible via PowerShell's `FileInfo` properties (such as the `$MFT` record's own modification time), and it can set all four timestamp fields in a single operation with arbitrary target values.

Both the defended and undefended variants completed without interference from endpoint controls.

## What This Dataset Contains

The technique execution is captured in Security EID 4688 with the full command line: `"powershell.exe" & {import-module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\timestomp.ps1" timestomp -dest "C:\AtomicRedTeam\atomics\..\ExternalPayloads\kxwn.lock"}`. Two operations are visible in this block: first, loading the `timestomp.ps1` module via `import-module`, and second, calling the `timestomp` function with a `-dest` parameter pointing to the target file.

Sysmon EID 1 captures the same process launch with tag `technique_id=T1059.001,technique_name=PowerShell`, with parent `powershell.exe`. The parent `powershell.exe` is the ART orchestration process.

Sysmon EID 7 records 20 image load events into the two PowerShell processes. The loads include:
- `.NET` runtime components: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll` (tagged `technique_id=T1055` by Sysmon rules — a false-positive tag on normal .NET initialization)
- Windows Defender integration: `MpOAV.dll`, `MpClient.dll` (tagged `technique_id=T1574.002,technique_name=DLL Side-Loading` — another Sysmon rule false-positive on normal Defender module loads)
- `urlmon.dll` (untagged — loaded by the .NET runtime infrastructure)

The `MpOAV.dll` and `MpClient.dll` loads are notable: even in the "undefended" (Defender-disabled) environment, these DLLs are still present in the Sysmon image load telemetry, because the Defender service's modules remain registered in the system even when Defender is disabled. They are loaded by PowerShell as part of the AMSI integration and do not indicate active Defender scanning.

The cleanup ART script block (`try { Invoke-AtomicTest T1070.006 -TestNumbers 8 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`) appears in PowerShell EID 4104.

PowerShell script block logging (EID 4104) captures 107 events. Sysmon EID 10 records process access events, EID 17 records named pipe creation.

The dataset contains 142 total events: 107 PowerShell, 4 Security, and 31 Sysmon.

## What This Dataset Does Not Contain

The content of `timestomp.ps1` is not captured. PowerShell script block logging would record the module's contents when it is imported via `import-module`, but the script block events in this dataset's sample set do not include the module source code. The module's internal implementation — what timestamps it sets, to what values, and via what API — is not visible from this event data.

There are no file metadata change events. Sysmon EID 2 (file creation time changed) was not enabled for the `ExternalPayloads` directory, so the actual timestamp modifications applied to `kxwn.lock` are not recorded. Neither the original nor the post-modification timestamps appear in any event.

No Security EID 4663 (file access) events are present — object access auditing was not enabled.

No DLL loading events specific to `timestomp.ps1`'s own dependencies are present (assuming it imports any external modules). The EID 7 records show only standard .NET and Defender integration DLLs loaded into the PowerShell process.

No network activity, registry modifications, or WMI events are present.

## Assessment

The dataset captures the technique execution at the command-line level with full fidelity. The module import and function invocation are visible in the process creation event. However, this dataset provides less insight into the actual timestomping mechanism than a dataset with Sysmon EID 2 or Security EID 4663 coverage would.

The use of a dedicated timestomping module (`timestomp.ps1`) rather than inline property assignment represents a higher-sophistication approach, but the process creation telemetry is similar in structure to T1070.006-5 and T1070.006-6. The key distinguishing feature is the `import-module` pattern and the use of a tool-specific function name (`timestomp`) as a command.

Compared to the defended variant (36 Sysmon, 10 Security, 49 PowerShell), the undefended run has a comparable Sysmon count (31 vs. 36) and more PowerShell events (107 vs. 49). The technique execution profile is substantively identical between the two variants — neither Defender nor any endpoint control detected or blocked the timestomping operation.

The image load events showing `MpOAV.dll` and `MpClient.dll` in Sysmon EID 7 serve as a reminder that "Defender disabled" does not mean Defender DLLs are absent from process memory. AMSI integration modules are loaded into PowerShell by the runtime regardless of Defender's operational state, and Sysmon's rule tagging of these loads as `T1574.002` (DLL Side-Loading) is a rule false-positive.

## Detection Opportunities Present in This Data

**`import-module ... timestomp.ps1` in PowerShell command line:** The module filename `timestomp.ps1` is visible in Security EID 4688 and Sysmon EID 1. This is an explicit indicator — a module named `timestomp` loaded by PowerShell has no legitimate use. Even if an attacker renames the module, detection logic looking for `import-module` followed by `timestomp` as a function call provides a reliable second layer.

**`timestomp -dest <path>` function invocation pattern:** The function call `timestomp -dest "<file>"` in a PowerShell command line is directly captured. The `-dest` parameter convention is specific to this tool's interface. Any similar timestomping tool with a different name would still exhibit the `import-module <external_script> <function> -dest <file>` pattern.

**`import-module` targeting files in `ExternalPayloads` or non-standard paths:** Legitimate PowerShell module loading uses `Install-Module` or loads from standard module paths (`$PSModulePath`). `import-module` loading a `.ps1` file (rather than a `.psd1` manifest or `.psm1` module file) from an arbitrary directory like `C:\AtomicRedTeam\...\ExternalPayloads\` is characteristic of a dropped or staged custom tool.

**Sysmon EID 2 coverage gap:** This dataset provides a clear example of the detection gap created by the absence of Sysmon EID 2 monitoring. A Sysmon configuration with EID 2 rules covering the `ExternalPayloads` directory would capture the timestamp modification event directly, including the new timestamp values applied to `kxwn.lock`. Testing EID 2 coverage against this dataset will confirm whether your Sysmon configuration catches the actual timestamp modification versus relying solely on command-line inspection.
