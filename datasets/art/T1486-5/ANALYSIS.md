# T1486-5: Data Encrypted for Impact — PureLocker Ransom Note

## Technique Context

T1486 (Data Encrypted for Impact) covers ransomware and encryption-as-sabotage. PureLocker is a ransomware family notable for its cross-platform implementation in PureBasic, use in targeted enterprise attacks, and its association with more_eggs malware. This test simulates a specific behavioral artifact of PureLocker: writing a ransom note file to the victim's desktop. Dropping a ransom note is a terminal indicator of ransomware execution and a high-confidence detection signal, even when the actual encryption binary is absent or blocked.

## What This Dataset Contains

The test writes a ransom note (`YOUR_FILES.txt`) to the desktop using a simple cmd.exe redirect. Security EID 4688 captures the command:

```
"cmd.exe" /c echo T1486 - Purelocker Ransom Note > %USERPROFILE%\Desktop\YOUR_FILES.txt
```

The parent process is `powershell.exe` (the ART test framework). Sysmon EID 11 (FileCreate) records the file creation:

```
Image: C:\Windows\system32\cmd.exe
TargetFilename: C:\Windows\System32\config\systemprofile\Desktop\YOUR_FILES.txt
```

The file lands in the SYSTEM profile's Desktop (since the test framework runs as SYSTEM), not a user desktop. This is an artifact of the test execution context. A real PureLocker infection would write to a user-context desktop path.

Sysmon EID 1 captures `cmd.exe` spawned from `powershell.exe`, tagged `technique_id=T1059.003`. Both `cmd.exe` exits exit cleanly (0x0), confirming the ransom note was written successfully. The PowerShell channel contains only boilerplate.

## What This Dataset Does Not Contain

There is no actual encryption activity in this dataset. PureLocker's encryption engine (AES-256 in CBC mode encrypting files with `.CR1` extension, typically) is not present — this is a note-drop simulation only. There are no file rename or extension-change events (EID 11 for encrypted output files), no registry modifications, no network C2 traffic, and no shadow copy deletion (which PureLocker performs via COM interfaces). The note content here is a placeholder string rather than the actual PureLocker ransom note text.

## Assessment

This is a minimal dataset that captures only the ransom note file drop. It is useful for testing file creation detections against known ransomware note filenames and for verifying that Sysmon EID 11 captures cmd.exe-based file writes. The data's value for detection engineering is limited to the file creation signal — it does not provide any coverage of PureLocker's actual behavioral profile (encryption, shadow copy deletion, persistence). Detection engineers can use this to validate filename-based rules but should pair it with a broader T1486 dataset for encryption behavior coverage.

## Detection Opportunities Present in This Data

1. **Sysmon EID 11 (FileCreate)**: File creation of `YOUR_FILES.txt` on the desktop — high-confidence ransomware note filename detection.
2. **Security EID 4688**: `cmd.exe` redirecting `echo` output to a desktop text file with a ransomware-associated filename pattern.
3. **Sysmon EID 1 + EID 11 correlation**: `cmd.exe` (spawned from `powershell.exe`) creating a `.txt` file on a desktop path within the same second — behavioral sequence for automated ransom note drops.
4. **Security EID 4688**: PowerShell spawning cmd.exe with an `echo ... > %USERPROFILE%\Desktop\` pattern — lateral detection for any file written to desktop via cmd redirect from a scripting host.
5. **Filename analytics**: Alerting on creation of known ransomware note filenames (`YOUR_FILES.txt`, `HOW_TO_DECRYPT.txt`, `RESTORE_FILES.txt`, etc.) regardless of writing process.
