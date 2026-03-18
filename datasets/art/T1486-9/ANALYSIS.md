# T1486-9: Data Encrypted for Impact — Data Encrypt Using DiskCryptor

## Technique Context

T1486 (Data Encrypted for Impact) includes full-disk and volume encryption tools repurposed by attackers. DiskCryptor is an open-source, legitimate disk encryption utility that has been observed in targeted ransomware campaigns — notably by the group behind the RagnarLocker ransomware, which deployed DiskCryptor as its encryption engine to encrypt entire volumes rather than individual files. This approach encrypts the file system at the block level, making forensic recovery extremely difficult and bypassing file-level AV scanning of the encrypted payload. Defenders focus on detecting DiskCryptor's binary (`dcrypt.exe`) being launched in enterprise environments where it has no legitimate administrative use.

## What This Dataset Contains

The test launches DiskCryptor's binary from its default installation path. Security EID 4688 captures:

```
"cmd.exe" /c ""%PROGRAMFILES%\dcrypt"\dcrypt.exe"
```

The parent process is `powershell.exe` running as `NT AUTHORITY\SYSTEM`. Sysmon EID 1 captures the cmd.exe wrapper (tagged `technique_id=T1059.003`). The cmd.exe process exits with code `0x1`, indicating DiskCryptor was not installed or the binary was blocked; no DiskCryptor process creation appears in either Sysmon EID 1 or Security EID 4688.

The dataset is compact (4-second window, 22:36:59–22:37:03). Sysmon EID 11 records only PowerShell startup profile file creation. The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

DiskCryptor (`dcrypt.exe`) itself does not appear as a process creation in any channel — either it was not pre-installed as a prerequisite or Windows Defender blocked its launch. No disk encryption activity, volume handle acquisition, or driver installation (DiskCryptor installs a kernel filter driver `dcrypt.sys`) is present in this telemetry. There are no Sysmon EID 6 (driver load) or EID 7 (image load) events for dcrypt components, and no registry writes for the DiskCryptor service. The test provides only the invocation attempt, not the encryption behavior itself.

## Assessment

This dataset represents an attempted execution where the target binary was absent or immediately blocked. Its primary value is the EID 4688 command line showing `dcrypt.exe` being invoked from the Program Files path via cmd.exe from PowerShell. This is sufficient for detecting DiskCryptor launch attempts. The absence of the actual DiskCryptor process, driver load, and encryption activity means this dataset cannot support detections based on DiskCryptor's kernel driver behavior or volume encryption patterns. Detection engineers should treat this as attempt telemetry. A pre-installation prerequisite step that verifies DiskCryptor is installed before the test runs would significantly improve dataset completeness.

## Detection Opportunities Present in This Data

1. **Security EID 4688**: Process creation for a binary at `%PROGRAMFILES%\dcrypt\dcrypt.exe` — presence of DiskCryptor in Program Files is itself anomalous in enterprise environments.
2. **Security EID 4688**: `cmd.exe` spawned from `powershell.exe` invoking a path containing `dcrypt` — string-based detection for DiskCryptor invocation attempts.
3. **Sysmon EID 1**: cmd.exe with `dcrypt.exe` in the command line, parent `powershell.exe` — same signal in the Sysmon channel.
4. **Presence analytics**: Any execution attempt of `dcrypt.exe` or file creation of `dcrypt.sys` in an environment where DiskCryptor is not an approved tool — zero-tolerance rule on the binary name.
5. **Security EID 4689**: cmd.exe exit code `0x1` immediately after a dcrypt invocation — failed launch attempt detection for environments monitoring failed execution patterns.
