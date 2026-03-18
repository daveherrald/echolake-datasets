# T1564.004-3: NTFS File Attributes — Create ADS via Command Prompt

## Technique Context

T1564.004 (NTFS File Attributes) includes the use of NTFS Alternate Data Streams (ADS) for data concealment and code storage. This test demonstrates ADS creation and execution using `cmd.exe` built-in redirection syntax (`echo ... > file.txt:stream.txt`), followed by reading from and executing the stream content using `for /f ... do %i`. This is a purely command-prompt technique requiring no external tools beyond `cmd.exe`, making it a minimal-footprint approach to hidden content storage and execution. Adversaries use this to stash small scripts or commands in a stream attached to an innocuous file and then execute the stream content without creating any conventional file in a watched directory.

## What This Dataset Contains

**Security 4688** captures the full `cmd.exe /c` command:
```
echo cmd /c echo "Shell code execution." > %temp%\T1564.004_has_ads_cmd.txt:adstest.txt
  & for /f "usebackq delims=?" %i in (%temp%\T1564.004_has_ads_cmd.txt:adstest.txt) do %i
```
A second 4688 records the executed stream content: `cmd /c echo "Shell code execution."`. Both `cmd.exe` instances exit with `0x0`, confirming the write, read, and execution of the ADS content all succeeded.

**Sysmon EID 15 (FileStreamCreate)** fires twice:
- First for the base file: `C:\Windows\Temp\T1564.004_has_ads_cmd.txt`
- Second for the named stream: `C:\Windows\Temp\T1564.004_has_ads_cmd.txt:adstest.txt`
  with hash `SHA256=B129DAF59DCD4F821E983EAB666C251F1DD7644B6D59BDE4FAF28817EBDE9A0D`

The SHA256 of the stream content is recorded, providing an IOC anchor for this specific ADS payload.

**Sysmon EID 1** captures the outer `cmd.exe` and a child `cmd.exe` corresponding to the `for /f ... do %i` executed stream content, with correct parent-child linkage.

**PowerShell 4103** captures the ART test framework `Set-ExecutionPolicy Bypass` boilerplate. No technique-specific PS content is logged because the technique itself is entirely within `cmd.exe`.

**4703 (Token Right Adjusted)** fires for the SYSTEM-context PowerShell session managing test execution.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 1 for the initial `cmd.exe` invocation appears — the sysmon-modular ProcessCreate include rules do not match `cmd.exe` in this context. Security 4688 provides coverage of the cmd.exe processes.

The ADS write itself (the echo redirect) does not produce a Sysmon EID 11 (FileCreate) for the stream — only EID 15 (FileStreamCreate) fires for named stream creation. The base file creation does generate an EID 15 record, which is slightly unusual since EID 15 is specifically for stream creation; in practice Sysmon generates EID 15 for the primary stream (`::$DATA`) as well when a new file is first written.

No network activity is present. The technique is entirely local filesystem and process execution.

## Assessment

The technique executed completely and successfully. ADS write, read, and command execution through the `for /f` loop all completed with exit code `0x0`. The dataset provides the ADS stream hash (Sysmon EID 15), the execution command line (Security 4688), and the spawned execution output (second cmd.exe 4688). This test is an excellent example of a fully cmd.exe-native ADS attack with no external dependencies.

## Detection Opportunities Present in This Data

- **Sysmon EID 15 with `:adstest.txt` (or any stream name) in TargetFilename**: this is the definitive ADS creation indicator. Any colon-separated stream name in an EID 15 TargetFilename path should be alerted.
- **4688 command line with `%temp%\...txt:adstest.txt` pattern**: the colon-in-path ADS syntax is visible in the Security log command line, enabling detection without Sysmon.
- **`for /f` loop executing from an ADS path**: the `for /f ... in (%temp%\file.txt:stream) do %i` construct is a rare but specific indicator of ADS-based command execution.
- **Second `cmd.exe` spawned from a `for /f` shell loop**: the executed stream content generates a child `cmd.exe` whose parent command line contains the ADS path — the parent-child pair with an ADS path in the parent's command line is a reliable detection compound.
- **SHA256 hash of stream content**: Sysmon EID 15 records the hash of the stream data, enabling retrospective IOC matching even after the stream is deleted.
