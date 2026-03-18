# T1566.002-1: Spearphishing Link — Paste and run technique

## Technique Context

T1566.002 (Spearphishing Link) covers initial access via links rather than attachments. The
"paste and run" variant — sometimes called ClickFix — is a social-engineering technique where
a webpage instructs the victim to open the Windows Run dialog (Win+R) or a terminal, paste
a command from the clipboard, and execute it. This bypasses browser-based download warnings,
email attachment scanning, and macro block policies entirely, as the victim types or pastes
the payload directly into an already-trusted interface. This ART test simulates the attacker
automation side: PowerShell uses `user32.dll` P/Invoke and `System.Windows.Forms` to
synthesize keyboard input (Win+R) and paste a command.

## What This Dataset Contains

The dataset spans approximately 10 seconds (14:28:28–14:28:38 UTC) from ACME-WS02.

**PowerShell 4104 (Script Block Logging)** records the full payload:

```
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class K {
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    }
"@
$VK_LWIN, $VK_R, $KEYDOWN, $KEYUP = 0x5B, 0x52, 0x0000, 0x0002
[K]::keybd_event($VK_LWIN, 0, $KEYDOWN, [UIntPtr]::Zero)
[K]::keybd_event($VK_R, 0, $KEYDOWN, [UIntPtr]::Zero)
...
```

The script uses `Add-Type` to compile C# that calls `keybd_event`, then synthesizes Win+R,
waits 500ms, types a command, and sends Enter. This inline C# compilation is the mechanism
that triggers `csc.exe` (C# compiler) execution.

**PowerShell 4103 (Module Logging)** records `Add-Type -TypeDefinition` (the C# P/Invoke
wrapper) and `Add-Type -AssemblyName System.Windows.Forms` (for clipboard operations), as
well as `Start-Sleep -Milliseconds 500` between keystrokes.

**Sysmon Event 1 (Process Create)** captures three key processes:
- `whoami.exe` (ART pre-flight, tagged T1033)
- `powershell.exe` with the full `keybd_event` command line (tagged T1059.001 PowerShell)
- `csc.exe` (C# compiler): `csc.exe /noconfig /fullpaths @"C:\Windows\SystemTemp\5idubglq\5idubglq.cmdline"` (tagged T1127 Trusted Developer Utilities Proxy Execution)

**Sysmon Event 7 (Image Load)** and **Event 10 (Process Access)** show PowerShell's normal
DLL injection-tagged startup activity, and PowerShell opening `csc.exe` with full access
(`0x1FFFFF`) as part of the `Add-Type` compilation flow.

**Sysmon Event 11 (File Created)** records the .NET compilation artifacts written to
`C:\Windows\SystemTemp\5idubglq\`: `.dll`, `.tmp`, `.0.cs`, `.cmdline`, `.err`, `.out`. These
are temporary files created by `Add-Type` during inline C# compilation.

**Security 4688/4689** records `powershell.exe`, `whoami.exe`, and `conhost.exe` lifecycle
events under SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No evidence of a command actually executing via the Run dialog.** This test was run under
`NT AUTHORITY\SYSTEM` via the QEMU guest agent — there is no interactive desktop session.
The `keybd_event` calls synthesize keystrokes into the kernel, but without a logged-on user
session showing a Run dialog, the pasted command has nowhere to land. No child process from
`explorer.exe` appears, and no Run dialog command execution is logged.

**No network activity.** The test simulates the UI interaction only; it does not include any
payload that would be pasted into the Run dialog. In a real ClickFix attack, the clipboard
would contain a `curl` or `mshta` command fetching a second-stage payload.

**No clipboard content in logs.** Windows does not natively log clipboard operations. The
content that would be "pasted" by the automation is only visible in the PowerShell script
block itself.

**No Sysmon ProcessCreate for cvtres.exe** in the main process list, though it appears in
Event 11 File Created as creating `RES2333.tmp`. The cvtres process (resource compiler, part
of .NET compilation) was not matched by Sysmon's process create include rules.

## Assessment

This dataset is notable for the `Add-Type` inline compilation chain: PowerShell 4104 captures
the C# source, 4103 captures the `Add-Type` call, Sysmon 1 captures `csc.exe` execution, and
Sysmon 11 captures the compilation artifacts. This multi-source chain is characteristic of
PowerShell scripts that need unmanaged API access. The `keybd_event` P/Invoke specifically is
rarely seen outside of automation tooling and offensive scripts.

The paste-and-run technique itself is not executed successfully in this headless environment,
but the tooling used to implement it generates a clear multi-source signature.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `Add-Type` with inline C# containing `DllImport("user32.dll")` and
  `keybd_event` is a strong indicator of keyboard simulation. `keybd_event` combined with
  virtual key code `0x5B` (VK_LWIN) is particularly specific to ClickFix-style automation.

- **Sysmon Event 1 + csc.exe**: `csc.exe` spawned from `powershell.exe` with a
  `SystemTemp\` path for the `.cmdline` file indicates `Add-Type` inline C# compilation.
  Correlate with the 4104 event to see the compiled code.

- **Sysmon Event 11**: Compilation artifacts (`.cmdline`, `.0.cs`, `.dll`) appearing under
  `C:\Windows\SystemTemp\` within seconds of each other indicate inline C# compilation.

- **PowerShell 4103**: `Add-Type -AssemblyName System.Windows.Forms` combined with
  keyboard simulation in the same session warrants investigation.

- **Security 4688**: Full command line visible for `powershell.exe` including `keybd_event`
  and `VK_LWIN` references when command-line auditing is enabled.
