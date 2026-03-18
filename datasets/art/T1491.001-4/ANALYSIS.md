# T1491.001-4: Internal Defacement — Ransom Note via Notepad (Non-Destructive)

## Technique Context

T1491.001 (Internal Defacement) encompasses adversary actions that make a visible statement to users that a system has been compromised. Displaying a ransom note as a text file opened in Notepad is a common pattern observed in ransomware incidents — after encryption completes, attackers drop `README.txt`, `DECRYPT_FILES.txt`, or similar files and open them in Notepad (or set them to open automatically) so that the victim immediately understands the situation. This test simulates that behavior in a non-destructive way: it writes a clearly labeled test ransom note to `%TEMP%` and opens it in Notepad. The detection value is in the artifacts — ransom-themed file names, PowerShell writing text files to temp directories, and Notepad launched with a suspicious file argument.

## What This Dataset Contains

The technique is executed via an inline PowerShell script. Security Event ID 4688 captures the complete command line including the ransom note content:

```
powershell.exe & {
  $notePath = Join-Path $env:TEMP "ART-T1491-ransom-note.txt"
  $Title = "!!! READ_ME_NOW !!!"
  $Body = "Your files are SAFE. This is a TEST note for detection validation..."
  [System.IO.File]::WriteAllText($notePath, $content, [System.Text.Encoding]::UTF8)
  $p = Start-Process notepad.exe -ArgumentList "`"$notePath`"" -PassThru
  $p.Id | Out-File -FilePath $pidPath -Encoding ascii -Force
}
```

Sysmon Event ID 11 (FileCreate) confirms the file artifacts: `C:\Windows\Temp\ART-T1491-ransom-note.txt` and `C:\Windows\Temp\ART-T1491-notepad.pid` are both created by `powershell.exe`. Security Event ID 4688 captures `notepad.exe` launched with the argument `"C:\Windows\TEMP\ART-T1491-ransom-note.txt"` — the Notepad process launch with the ransom note path is explicitly visible. The parent process is `powershell.exe` (SYSTEM context). The ransom note title `!!! READ_ME_NOW !!!` appears in the command line captured in the Security 4688 event for the PowerShell process, making keyword detection on characteristic ransom note strings possible directly from process event data.

## What This Dataset Does Not Contain

- **No encryption activity**: This test is explicitly non-destructive; there are no file modification or deletion events that would indicate actual ransomware encryption.
- **No Sysmon ProcessCreate for `notepad.exe`**: Sysmon's include-mode ProcessCreate filtering does not have a rule matching `notepad.exe`, so the Notepad launch is absent from the Sysmon channel. The Security 4688 channel provides coverage for this process creation.
- **No PowerShell 4104 script block with the ransom note body text**: Unlike T1491.001-2, the PowerShell channel in this dataset contains only test framework boilerplate. The `[System.IO.File]::WriteAllText` call does not trigger a distinct script block entry beyond what is already captured in the Security 4688 command line.
- **No persistence mechanism**: Opening a file in Notepad is a one-time action; there is no startup entry, scheduled task, or registry modification to re-display the note on subsequent logins.

## Assessment

This dataset is compact but well-targeted. The ransom note filename (`ART-T1491-ransom-note.txt`), the characteristic title string (`!!! READ_ME_NOW !!!`), the file creation in `%TEMP%`, and Notepad launched by SYSTEM-context PowerShell with a `.txt` file argument are all present across Security and Sysmon channels. The dataset is well-suited for testing detection rules around ransom-note file creation patterns and Notepad used as a display vehicle for malicious content. The absence of Sysmon coverage for `notepad.exe` process creation is a gap worth noting for defenders who rely solely on Sysmon.

## Detection Opportunities Present in This Data

1. **Security 4688 capturing `notepad.exe` launched by `powershell.exe` (SYSTEM) with a `.txt` file path in `%TEMP%`** — The parent-child relationship (PowerShell spawning Notepad to open a temp file) and the SYSTEM integrity level are both unusual.
2. **Sysmon Event ID 11 showing `.txt` file creation in `%TEMP%` by `powershell.exe`** — File creation of a ransom-note-named `.txt` file in a temp directory by PowerShell is a low-prevalence pattern.
3. **Command-line keyword matching on ransom note title strings** — Security 4688 captures `!!! READ_ME_NOW !!!` in the PowerShell command line; similar keyword matches apply to real-world ransom note titles.
4. **`.pid` file creation alongside a `.txt` file by the same PowerShell process** — The `ART-T1491-notepad.pid` file tracking the Notepad PID is an artifact of the scripted pattern; writing a `.pid` file to track a user-facing process is atypical of legitimate applications.
5. **SYSTEM-context `notepad.exe` launched with a text file argument** — Notepad opening a `.txt` file under NT AUTHORITY\SYSTEM is unusual in most enterprise environments and warrants review regardless of filename content.
