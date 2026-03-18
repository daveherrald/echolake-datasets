# T1555.003-8: Credentials from Web Browsers — Decrypt Mozilla Passwords with Firepwd.py

## Technique Context

T1555.003 (Credentials from Web Browsers) includes active decryption of Firefox credential stores using purpose-built tools. Firepwd.py is an open-source Python tool that reads Firefox's `key4.db` (NSS key database) and `logins.json` to decrypt saved passwords without requiring the Firefox master password (if none is set). This represents a more complete attack than file-copying — it demonstrates on-system decryption and plaintext credential recovery.

## What This Dataset Contains

The dataset spans six seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The core action was a PowerShell script block that invoked Firepwd.py via a pre-staged Python virtual environment:

```powershell
$PasswordDBLocation = get-childitem -path "$env:appdata\Mozilla\Firefox\Profiles\*.default-release\"
cmd /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1555.004\Scripts\python.exe \
    C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1555.004\Scripts\Firepwd.py \
    -d $PasswordDBLocation > $env:temp\T1555.003Test8.txt
cat $env:temp\T1555.003Test8.txt
```

This script block appears in EID 4104 twice (invocation and bare form). The output was redirected to `%TEMP%\T1555.003Test8.txt`.

Sysmon events include:
- **EID 1** (Process Create): `whoami.exe` (T1033) and a `powershell.exe` child (T1059.001) — both test framework-invoked
- **EID 7** (ImageLoad): DLLs loaded into PowerShell processes
- **EID 10** (ProcessAccess): Cross-process PowerShell access (T1055.001)
- **EID 11** (FileCreate): PowerShell transcript file plus a notable file written to `C:\Windows\Temp\` tagged `T1574.010` (Services File Permissions Weakness) — likely a transient temp file from Python/Firepwd.py execution
- **EID 17** (PipeCreate): Named PSHost pipes

Security events: EID 4688/4689/4703 for SYSTEM context processes.

Additional sources:
- **System EID 7040**: Background Intelligent Transfer Service (BITS) start type changed from auto to demand — a side effect of the test environment, not directly related to this technique.
- **WMI EID 5858**: Failed WMI query `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — an ART test framework attempt to monitor WinRM host processes that returned `0x80041032` (unsupported). This is test framework infrastructure noise.

## What This Dataset Does Not Contain (and Why)

**No EID 1 for python.exe or firepwd.py.** Sysmon's include-mode ProcessCreate rules do not match generic Python interpreter invocations — the actual Firepwd.py execution is invisible to Sysmon here. Security EID 4688 is also absent for python.exe because the SYSTEM account's process creation logging captured only the PowerShell and cmd.exe parents in the time window.

**No file read events for key4.db or logins.json.** Object access auditing is disabled.

**No decrypted credential content.** The output file `T1555.003Test8.txt` was written but its contents are not captured in event logs.

**No LSASS access.** Firefox credential decryption operates entirely on NSS database files — no in-memory credential extraction required.

## Assessment

This is the most operationally significant of the three T1555.003 datasets. The presence of Firepwd.py indicates a deliberate tool deployment (pre-staged in `ExternalPayloads\venv_t1555.004`) and on-system decryption rather than mere file exfiltration. The EID 4104 script block is the clearest detection artifact, revealing both the tool path and the `get-childitem` enumeration of the Firefox profile directory. The WMI EID 5858 failure is test framework overhead and not technique-relevant.

## Detection Opportunities Present in This Data

- **EID 4104**: Script block references `Firepwd.py` and `venv_t1555.004\Scripts\python.exe` — both are high-confidence indicators. Any PowerShell invoking `Firepwd.py` is immediately suspicious.
- **EID 4104**: `get-childitem` targeting `$env:appdata\Mozilla\Firefox\Profiles\*.default-release\` is a specific enumeration of the Firefox credential location.
- **EID 11 (Sysmon)**: Output file creation in `C:\Windows\Temp\T1555.003Test8.txt` — file names matching `T1555*` are artifact of ART but any `firepwd` or password-dump output in Temp is worth hunting.
- **EID 4688**: `cmd.exe` spawned from PowerShell under SYSTEM — while not unique, the parent-child chain `powershell.exe → cmd.exe → python.exe` is unusual for normal workstation activity.
- **File system hunting**: Presence of `key4.db` access or `Firepwd.py` on disk outside browser install paths is a strong indicator of credential theft tooling.
