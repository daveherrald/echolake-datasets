# T1547.009-1: Shortcut Modification — Shortcut Modification - Shortcut Modification

## Technique Context

T1547.009 (Shortcut Modification) covers adversary use of Windows shortcut files (.lnk, .url) to establish persistence or redirect execution. By creating or modifying shortcut files, attackers can execute arbitrary payloads when users interact with the shortcuts or when the system processes them at startup. Test 1 focuses on creating a `.url` (Internet Shortcut) file pointing to a calculator executable, simulating the modification of a shortcut to redirect execution. Real-world abuse of this technique includes placing malicious shortcuts in the Startup folder, in common locations like the Desktop, or modifying existing shortcuts to wrap a legitimate application.

## What This Dataset Contains

The test uses `cmd.exe` to write a `.url` Internet Shortcut file to the TEMP directory. A Sysmon EID 1 (ProcessCreate) captures the command with the rule tag `technique_id=T1059.003,technique_name=Windows Command Shell`:

```
Process Create:
  Image: C:\Windows\System32\cmd.exe
  CommandLine: "cmd.exe" /c echo [InternetShortcut] > %temp%\T1547.009_modified_shortcut.url
               & echo URL=C:\windows\system32\calc.exe >> %temp%\T1547.009_modified_shortcut.url
               & %temp%\T1547.009_modified_shortcut.url
  User: NT AUTHORITY\SYSTEM
```

A Sysmon EID 11 (FileCreate) records the resulting file creation with the tag `technique_id=T1574.010,technique_name=Services File Permissions Weakness`:

```
File created:
  Image: C:\Windows\system32\cmd.exe
  TargetFilename: C:\Windows\Temp\T1547.009_modified_shortcut.url
```

The tag mismatch (T1574.010 rather than T1547.009) reflects that the sysmon-modular ruleset does not have a specific rule for this file path, but the TEMP directory file creation matches a general writable-directory pattern.

The test framework runs `whoami.exe` first (Sysmon EID 1, T1033), then spawns `cmd.exe` via PowerShell. No PowerShell EID 4104 entries contain the cmd command — this test invokes cmd directly from the ART test framework rather than as a PowerShell script block, so the 4104 log shows only boilerplate formatter entries.

Sysmon event counts: 25 events across EID 1 (3), EID 7 (14), EID 10 (2), EID 11 (3), EID 17 (3). Security events: 15 events (4688 × 5, 4689 × 9, 4703 × 1).

## What This Dataset Does Not Contain

**Shortcut execution telemetry is absent.** The test appends `& %temp%\T1547.009_modified_shortcut.url` to open the shortcut immediately after creation, but no child `calc.exe` process creation is recorded in the captured window. The URL handler for `.url` files would invoke a browser or URL handler — the execution may have been blocked or may fall outside the event capture scope.

**No .lnk (binary shortcut) creation** — this test uses a text-format `.url` file rather than a compiled `.lnk` binary, so the more commonly analysed LNK file format is not represented.

**No PowerShell script block content** for this test — the cmd.exe invocation does not generate a substantive PowerShell EID 4104, so there is no script block with the attack logic visible.

**No Startup folder placement** — the shortcut is written to TEMP, not to a persistence-relevant location. Startup folder placement is tested in T1547.009-2.

**Object access auditing is disabled**, so no file audit events (4663) are present.

## Assessment

The test ran to completion. The `.url` file creation is confirmed by Sysmon EID 11, and the full cmd.exe command line is captured in Sysmon EID 1. The test represents the file-write phase of shortcut modification persistence. The Sysmon rule mislabels this as T1574.010, but the file creation event is still captured. Detection engineers should note that the primary signal here comes from the cmd.exe command line rather than from a registry event.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: The `cmd.exe` command line shows the echo-redirect pattern writing a `.url` file with a `URL=` pointing to a system binary (`calc.exe`). Alerting on `.url` file creation via cmd.exe echo redirection is effective.
- **Sysmon EID 11**: File creation of `.url` files in writable directories (TEMP, user profile) by shells (`cmd.exe`, `powershell.exe`) is suspicious and relatively rare in legitimate use.
- **Security EID 4688**: The `cmd.exe` process creation includes the full command line, providing a second independent detection source.
- **Behavioral sequence**: `whoami.exe` execution immediately before `cmd.exe` writing a shortcut file is a reliable ART behavioral pattern but also resembles real attacker enumeration-then-persist behavior.
- A rule matching `echo [InternetShortcut]` in process command lines would be a reliable, low-noise indicator for this specific technique variant.
