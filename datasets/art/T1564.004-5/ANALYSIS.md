# T1564.004-5: NTFS File Attributes — Create Hidden Directory via $index_allocation

## Technique Context

T1564.004 (NTFS File Attributes) extends beyond Alternate Data Streams to other NTFS metadata attributes. This test exploits the NTFS `$INDEX_ALLOCATION` attribute, which is the internal B-tree index that stores directory entries. By appending `::$index_allocation` to a `md` (mkdir) command, an attacker forces NTFS to interpret the target as an index-allocation object name rather than a standard directory. This creates a directory with a name that includes dots and dollar signs (`...$.......`) that standard Windows shell tools (`dir`, Explorer, `rmdir`) cannot enumerate or delete by normal means. Files placed inside this directory are hidden from conventional filesystem browsing, though they remain accessible via their full path.

## What This Dataset Contains

**Security 4688** records the full command:
```
cmd.exe /c md %temp%\...$.......::$index_allocation
  & echo too many secrets > %temp%\...$.......::$index_allocation\secrets.txt
```
`cmd.exe` exits with `0x0`, confirming both the directory creation and the file write succeeded.

**Sysmon EID 11 (FileCreate)** records two file creation events by `cmd.exe`:
- `C:\Windows\Temp\...$.......\` — the directory object itself
- `C:\Windows\Temp\...$.......\secrets.txt` — the file written inside the hidden directory

Both entries show the unusual dot-and-dollar directory name in their paths. The `secrets.txt` creation confirms the hidden directory is functional as a container.

**Sysmon EID 1** captures the `cmd.exe` invocation (matched by sysmon-modular as a suspicious command-line pattern) and the ART test framework `whoami.exe` prerequisite check, both with full command lines and parent PowerShell linkage.

**PowerShell 4103** captures the ART test framework boilerplate (`Set-ExecutionPolicy Bypass`). No technique content appears in PowerShell logging because the technique executes entirely within `cmd.exe`.

**4703 (Token Right Adjusted)** fires for the SYSTEM PowerShell session.

## What This Dataset Does Not Contain (and Why)

No Sysmon EID 15 (FileStreamCreate) appears. This technique does not create a named stream on an existing file — it exploits the `$index_allocation` attribute to create a directory with an obfuscated name. The resulting object is a directory entry, not a file stream, so EID 15 does not fire.

No Sysmon EID 12/13/14 (Registry) events appear. The technique is purely filesystem-based.

The `::$index_allocation` suffix does not appear in the Sysmon EID 11 `TargetFilename` field — the path is recorded as `C:\Windows\Temp\...$.......\secrets.txt`, showing the resolved canonical directory path without the NTFS attribute syntax used at creation time. This is expected: by the time Sysmon's kernel-mode driver records the file creation, Windows has already resolved the object name.

## Assessment

The technique executed successfully. A hidden directory was created and a file was written inside it. The dataset provides the creation command line (Security 4688) and the resulting filesystem artifacts (Sysmon EID 11). The unusual directory name `...$.......\` is visible in the Sysmon EID 11 TargetFilename, providing a detectable artifact even without the `::$index_allocation` syntax being preserved in the log.

## Detection Opportunities Present in This Data

- **4688 command line containing `::$index_allocation`**: this NTFS attribute syntax in a `md` or `mkdir` command is a high-confidence indicator with effectively no legitimate use in enterprise environments. The string `$index_allocation` in any command line should trigger an alert.
- **Sysmon EID 11 with an anomalous directory name** containing repeating dots and dollar signs (e.g., `...$.......\`): the unusual directory name pattern in a file path is detectable by regex without requiring knowledge of the creation syntax.
- **`cmd.exe` creating files in `%temp%\...$` paths**: paths beginning with `...$` in TEMP directories are highly anomalous and warrant investigation regardless of whether `$index_allocation` is visible.
- **`cmd.exe` with both `md` and `echo ... > path\secrets.txt` in a single chain**: creating a directory and immediately writing to it in one chained command is a pattern consistent with adversary staging activity.
- **Sysmon EID 11 TargetFilename containing repeated non-alphanumeric characters**: broader detection for obfuscated directory names can catch variants that use different character combinations.
