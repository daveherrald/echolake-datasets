# T1546.011-1: Application Shimming — Application Shim Installation

## Technique Context

T1546.011 (Application Shimming) exploits the Windows Application Compatibility framework, which was designed to allow legacy applications to run on newer versions of Windows by transparently intercepting API calls and applying compatibility fixes. Shim databases (`.sdb` files) are installed via `sdbinst.exe` and register compatibility entries in the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\`. When a targeted application runs, Windows loads the shim DLL into the process before execution. Attackers abuse this to achieve persistent code execution in the context of a legitimate application without modifying the application's binary. The technique requires elevation but produces registry and file artifacts that are reliably detectable. Detection focuses on `sdbinst.exe` execution, `.sdb` file writes to `C:\Windows\AppPatch\CustomSDB\`, and registry writes under `AppCompatFlags\Custom\`.

## What This Dataset Contains

Sysmon EID 1 records three process creates, including the core execution artifact — `sdbinst.exe` with a direct rule match on the technique:

```
RuleName: technique_id=T1546.011,technique_name=Application Shimming
Image: C:\Windows\System32\sdbinst.exe
CommandLine: sdbinst.exe "C:\AtomicRedTeam\atomics\T1546.011\bin\AtomicShimx86.sdb"
```

The parent is `cmd.exe` (`CommandLine: "cmd.exe" /c sdbinst.exe "C:\AtomicRedTeam\atomics\T1546.011\bin\AtomicShimx86.sdb"`, tagged `T1059.003`), which in turn was spawned from `powershell.exe`.

Sysmon EID 11 (FileCreate) captures the shim database being installed to its permanent location:

```
RuleName: technique_id=T1546.011,technique_name=Application Shimming
Image: C:\Windows\system32\sdbinst.exe
TargetFilename: C:\Windows\apppatch\CustomSDB\{084c9f6c-a911-44f5-aecf-6a9a55b93c43}.sdb
```

Sysmon EID 13 (RegistryValueSet) captures six registry writes by `sdbinst.exe`, all tagged `T1546.011`:

- `AppCompatFlags\Custom\AtomicTest.exe\{084c9f6c-...}.sdb` — the target application entry
- `AppCompatFlags\InstalledSDB\{084c9f6c-...}\DatabaseRuntimePlatform` (DWORD 4)
- `AppCompatFlags\InstalledSDB\{084c9f6c-...}\DatabaseDescription` = `AtomicShim`
- `AppCompatFlags\InstalledSDB\{084c9f6c-...}\DatabaseType` (DWORD 0x10000)
- `AppCompatFlags\InstalledSDB\{084c9f6c-...}\DatabasePath` = `C:\Windows\AppPatch\CustomSDB\{084c9f6c-...}.sdb`
- `AppCompatFlags\InstalledSDB\{084c9f6c-...}\DatabaseInstallTimeStamp`

The GUID `{084c9f6c-a911-44f5-aecf-6a9a55b93c43}` appears in both the `.sdb` filename and all registry keys, providing a consistent cross-event correlation anchor.

Sysmon EID 7 includes an unusual image load for `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpClient.dll` into `powershell.exe`, tagged `T1574.002` (DLL Side-Loading) — this reflects Defender's AMSI integration loading its client DLL into the PowerShell process. It is a test framework artifact, not part of the shimming technique.

Security EID 4688 records three process creations (including `sdbinst.exe` as SYSTEM). EID 4689 records nine terminations. One EID 4703 is present.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

The shim database file at `C:\AtomicRedTeam\atomics\T1546.011\bin\AtomicShimx86.sdb` (the source `.sdb` file) is not created during this test window — it was pre-staged as part of ART setup. The actual shim DLL that would be loaded by the targeted application (`AtomicTest.exe`) is not present in this dataset, and there is no EID 7 for the shim DLL loading because `AtomicTest.exe` is never executed. The shim registration covers the setup phase only; runtime behavior of the shim would require a separate execution dataset. Object access auditing is disabled, so there are no EID 4663 events for the `.sdb` file copy into `CustomSDB\`.

## Assessment

This is an excellent dataset for Application Shimming detection. It contains the complete installation fingerprint: the `sdbinst.exe` process creation (tagged on the correct technique), the `.sdb` file written to `CustomSDB\`, and six registry writes under `AppCompatFlags\` that together describe the full shim registration state. The GUID linking all artifacts makes cross-event correlation straightforward. The DatabaseDescription value `AtomicShim` appearing in EID 13 is a useful example of a named shim that would stand out in any registry monitoring. A detection rule keying on `sdbinst.exe` execution with a source `.sdb` from a non-standard path (i.e., not `%windir%\AppPatch\`) would catch this pattern reliably.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `sdbinst.exe` execution with a `.sdb` file path outside `C:\Windows\AppPatch\`** (e.g., from `C:\AtomicRedTeam\` or any temp/user path) — tagged `T1546.011`; the source path indicates non-legitimate shimming.
2. **Sysmon EID 11 — FileCreate for a `.sdb` file in `C:\Windows\AppPatch\CustomSDB\`** by `sdbinst.exe` — shim database installation to the custom database directory.
3. **Sysmon EID 13 — RegistryValueSet to `AppCompatFlags\Custom\<executable name>\<GUID>.sdb`** by `sdbinst.exe` — shim targeting a specific application.
4. **Sysmon EID 13 — RegistryValueSet to `AppCompatFlags\InstalledSDB\<GUID>\DatabaseDescription`** with an unexpected or arbitrary string value — human-readable shim name aiding threat hunting.
5. **Security EID 4688 — `sdbinst.exe` process creation as SYSTEM from `cmd.exe`** with a `.sdb` file path argument in a non-standard location.
6. **Correlation: EID 1 `sdbinst.exe` + EID 11 `.sdb` FileCreate in `CustomSDB\` + EID 13 `AppCompatFlags\Custom\` write, all sharing the same GUID within milliseconds** — complete shim installation fingerprint.
