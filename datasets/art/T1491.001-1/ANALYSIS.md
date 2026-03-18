# T1491.001-1: Internal Defacement — Replace Desktop Wallpaper

## Technique Context

T1491.001 (Internal Defacement) describes adversary actions that modify internal systems to intimidate, mislead, or make a statement — commonly seen in ransomware operations (changing the desktop wallpaper to a ransom demand), nation-state operations, and destructive attacks. Replacing the desktop wallpaper is one of the most visible and immediate psychological-impact moves an attacker can make. It signals to every logged-in user that the system has been compromised and that the attacker controls the environment. Detection teams care about this because it often marks the final, noisy phase of a ransomware attack after encryption has already occurred. Catching wallpaper replacement in real time means the attacker has already achieved significant objectives.

## What This Dataset Contains

The technique is executed entirely in PowerShell. Security Event ID 4688 and Sysmon Event ID 1 both capture the PowerShell process creation with the full inline script as the command line:

```
powershell.exe & {
  $url = "https://redcanary.com/wp-content/uploads/Atomic-Red-Team-Logo.png"
  $imgLocation = "$env:TEMP\T1491.001-newWallpaper.png"
  $orgWallpaper = (Get-ItemProperty -Path Registry::'HKEY_CURRENT_USER\Control Panel\Desktop\' -Name WallPaper).WallPaper
  $orgWallpaper | Out-File -FilePath "$env:TEMP\T1491.001-OrginalWallpaperLocation"
  $updateWallpapercode = @' ... [Add-Type Win32 SystemParametersInfo P/Invoke] ... '@
  $wc = New-Object System.Net.WebClient
  $wc.DownloadFile($url, $imgLocation)
  add-type $updateWallpapercode
  [Win32.Wallpaper]::SetWallpaper($imgLocation)
}
```

The dataset captures the full execution chain including side effects: Sysmon Event ID 11 (FileCreate) shows `C:\Windows\Temp\T1491.001-newWallpaper.png` and `C:\Windows\Temp\T1491.001-OrginalWallpaperLocation` being created by `powershell.exe`. The C# compilation artifact chain is visible — `csc.exe` is spawned by PowerShell to compile the `add-type` inline code, producing files under `C:\Windows\SystemTemp\qb54gqwg\` (a random temp directory), including the compiled DLL. This is a reliable artifact of PowerShell's `Add-Type` for wallpaper-setting P/Invoke code. Sysmon Event ID 22 (DNS query) shows `QueryName: redcanary.com` resolved to `104.198.136.223` immediately before the download, with Event ID 3 (NetworkConnect) recording a Defender MsMpEng.exe connection (likely Defender scanning the download). Sysmon Event ID 1 captures both the parent `powershell.exe` and the child `csc.exe` (compiler) and `cvtres.exe` (resource compiler) processes.

## What This Dataset Does Not Contain

- **The actual network download connection from `powershell.exe`**: The Sysmon Event ID 3 present in the dataset records a connection from `MsMpEng.exe` to the same IP, not from `powershell.exe` itself. The PowerShell WebClient download may have succeeded prior to Sysmon capturing the connection, or the sysmon-modular network monitoring did not capture that specific `powershell.exe` outbound connection during the collection window. The file `T1491.001-newWallpaper.png` was created, so the download succeeded.
- **Sysmon Event ID 13 (RegistryValue Set) for the wallpaper registry key**: The `SystemParametersInfo` Win32 API sets the wallpaper, and the change would also update `HKCU\Control Panel\Desktop\WallPaper`. This registry modification is not captured in the dataset — the sysmon-modular config's registry monitoring does not cover this path.
- **PowerShell channel technique content**: The PowerShell/Operational channel contains only ART test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy -Bypass`). The inline script block visible in the Sysmon/Security command-line fields does not appear in the PowerShell channel as a distinct script block log entry, likely because the technique script was passed as a command-line argument rather than as a file-based script.

## Assessment

This dataset provides strong technique coverage with good artifact diversity. The command-line content is rich and unambiguous — the full wallpaper-replacement script is captured twice (Sysmon Event ID 1 and Security 4688). The compilation artifact chain (`csc.exe`, temp DLL) is a useful secondary indicator. The DNS resolution to redcanary.com and the file creation of the PNG and original wallpaper location file round out the story. The dataset is well-suited for building detection rules around PowerShell-invoked wallpaper APIs, Add-Type compilation artifacts, and file creation patterns. Adding registry monitoring for `HKCU\Control Panel\Desktop\WallPaper` modifications would make it more complete.

## Detection Opportunities Present in This Data

1. **`powershell.exe` command line containing `SystemParametersInfo`, `SetWallpaper`, or `WallPaper` API references** — Security 4688 / Sysmon Event ID 1 captures the full inline script including Win32 P/Invoke code for wallpaper manipulation.
2. **`csc.exe` spawned by `powershell.exe` from a random temp directory** — Sysmon Event ID 1 shows `csc.exe` with a randomly named temp path in `C:\Windows\SystemTemp\`, a classic `Add-Type` compilation artifact.
3. **File creation of image files (PNG/JPG/BMP) in `%TEMP%` by `powershell.exe`** — Sysmon Event ID 11 captures `T1491.001-newWallpaper.png` written to `C:\Windows\Temp\` by PowerShell; this pattern is low-prevalence for SYSTEM-context PowerShell.
4. **DNS resolution to external domains immediately followed by file creation in `%TEMP%`** — Sysmon Event ID 22 (`redcanary.com`) combined with Event ID 11 within the same process session is a strong indicator of payload download.
5. **`powershell.exe` using `New-Object System.Net.WebClient` followed by `DownloadFile`** — Visible in the Security 4688 command-line field; this call pattern combined with wallpaper API invocation is highly characteristic of wallpaper-replacement defacement.
6. **File creation of an "original wallpaper location" backup file** — The `T1491.001-OrginalWallpaperLocation` file write by SYSTEM-context PowerShell indicates automated wallpaper manipulation with a restore-capable pattern.
