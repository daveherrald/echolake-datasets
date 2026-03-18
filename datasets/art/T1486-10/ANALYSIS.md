# T1486-10: Akira Ransomware — Drop Files with .akira Extension and Ransom Note

## Technique Context

T1486 (Data Encrypted for Impact) manifests in this test as Akira ransomware simulation. Akira is an active ransomware-as-a-service operation that emerged in 2023, targeting SMBs and enterprises across multiple sectors. It is characterized by double-extortion (encryption plus data exfiltration threats), a distinctive retro-styled victim portal, and use of both Windows and Linux/ESXi encryptors. This test simulates two Akira behaviors: writing files with `.akira` extensions (mimicking the encryption output) and dropping the Akira ransom note (`akira_readme.txt`) to the victim's desktop.

## What This Dataset Contains

The test uses a PowerShell loop to create 100 pseudo-encrypted files and then writes the ransom note. The PowerShell script block logging channel (EID 4104) captures the full attack payload:

```powershell
1..100 | ForEach-Object {
  $out = new-object byte[] 1073741
  (new-object Random).NextBytes($out)
  [IO.File]::WriteAllBytes("c:\test.$_.akira", $out)
}
echo "Hi friends" >> $env:Userprofile\Desktop\akira_readme.txt
echo "Whatever who you are and what your title is if you're reading this
      it means the internal infrastructure of your company is fully or
      partially dead, all your backups - virtual, physical - everything
      that we managed to reach - are completely removed..."
```

This is the actual Akira ransom note text. Security EID 4688 captures:
- PowerShell spawning a child `powershell.exe` with the `ForEach-Object` loop visible in the command line
- `whoami.exe` pre-execution context check

Sysmon EID 11 captures creation of `akira_readme.txt` at `C:\Windows\System32\config\systemprofile\Desktop\akira_readme.txt`. Sysmon EID 1 captures the PowerShell child process (tagged `technique_id=T1083`). Sysmon EID 3 records a network connection from Windows Defender (`MsMpEng.exe`) to `48.211.71.202:443` — this is Defender performing a cloud lookup in response to the suspicious activity, not the ransomware itself.

The `.akira` file creation events (100 files written to `c:\test.$_.akira`) did not produce Sysmon EID 11 records — the test files were created via `[IO.File]::WriteAllBytes` directly from PowerShell's process rather than through a path matched by sysmon-modular file creation rules.

## What This Dataset Does Not Contain

The 100 `.akira` files are written but do not generate Sysmon EID 11 events — `[IO.File]::WriteAllBytes` from within PowerShell is not matched by the sysmon-modular file create rules for this path pattern. There is no actual encryption of pre-existing user files — the test creates new random-byte files rather than encrypting existing documents. No shadow copy deletion (a standard Akira pre-encryption step via vssadmin or WMI) is present in this dataset. No network C2, data exfiltration, or lateral movement events are present. The file writes land in `c:\test.$_.akira` rather than user document directories, reflecting the SYSTEM execution context of the test framework.

## Assessment

This is one of the stronger datasets in this group because it captures technique-specific content in two channels simultaneously: the PowerShell EID 4104 script block contains the exact loop code and the full ransom note text, while Sysmon EID 11 captures the ransom note file creation. Detection engineers get both behavioral (file creation, mass write loop) and content-based (ransom note text strings, `.akira` extension) signals. The Windows Defender cloud lookup visible in Sysmon EID 3 is an interesting secondary signal — Defender detected something suspicious enough to trigger cloud intelligence querying.

## Detection Opportunities Present in This Data

1. **PowerShell EID 4104**: Script block containing `WriteAllBytes` in a loop creating files with a ransomware extension (`.akira`) — content-based detection of PowerShell-driven bulk file writing.
2. **Sysmon EID 11**: Creation of `akira_readme.txt` on the desktop — known Akira ransom note filename as a high-confidence indicator.
3. **Security EID 4688**: `powershell.exe` spawning a child `powershell.exe` with `ForEach-Object` and `WriteAllBytes` in the command line — anomalous PowerShell self-spawning with bulk write semantics.
4. **PowerShell EID 4104**: Script block containing Akira ransom note text strings ("Hi friends", "internal infrastructure of your company is fully or partially dead") — string matching against known ransom note content.
5. **Sysmon EID 11 + EID 4104 correlation**: Ransom note file creation coinciding with a PowerShell script block that creates files with unusual extensions — multi-source correlated detection.
6. **Sysmon EID 3**: `MsMpEng.exe` making outbound HTTPS connections during suspicious PowerShell activity — Defender cloud lookup as an indirect indicator that the endpoint AV flagged something.
7. **PowerShell EID 4104**: Use of `new-object byte[]` with a large fixed size followed by `NextBytes` (random byte fill) — signature of simulated encryption output generation.
