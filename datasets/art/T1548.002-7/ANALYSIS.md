# T1548.002-7: Bypass User Account Control — Bypass UAC using sdclt DelegateExecute

## Technique Context

T1548.002 (Bypass User Account Control) encompasses multiple auto-elevating binaries
that can be hijacked via HKCU registry manipulation. This test targets `sdclt.exe`
(Windows Backup and Restore), which checks
`HKCU\Software\Classes\Folder\shell\open\command` for a `DelegateExecute` value before
auto-elevating. By writing a command string and an empty `DelegateExecute` value to that
path, an attacker causes `sdclt.exe` to invoke the command at high integrity without
a UAC prompt. Unlike the Fodhelper variants (tests 3–5), this technique uses the
`Folder` shell handler rather than `ms-settings`, providing variation that may evade
`ms-settings`-specific detection rules.

The payload is delivered via a PowerShell child process.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:05:02–00:05:07 UTC).

**Security 4688 — three process creates:**
1. `whoami.exe` (ART pre-check, parent `powershell.exe`)
2. The payload PowerShell child:
   ```
   "powershell.exe" & {
     New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command"
              -Value 'cmd.exe /c notepad.exe'
     New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command"
                      -Name "DelegateExecute"
     Start-Process -FilePath $env:windir\system32\sdclt.exe
     Start-Sleep -s 3
   }
   ```
3. `sdclt.exe` launched directly (Token elevation type: `TokenElevationTypeDefault (1)`).

**PowerShell 4104 — script block logged:**
The full payload block is captured twice (creation and execution phases), explicitly
showing the `Folder\shell\open\command` path and `DelegateExecute` pattern.

**PowerShell 4103 — module logging:**
`New-Item` with `Value = 'cmd.exe /c notepad.exe'` and `New-ItemProperty` with
`Name = DelegateExecute` are recorded with full parameter bindings.

**Sysmon Event 13 — two registry writes confirmed:**
```
HKU\.DEFAULT\Software\Classes\Folder\shell\open\command\(Default) = cmd.exe /c notepad.exe
HKU\.DEFAULT\Software\Classes\Folder\shell\open\command\DelegateExecute = (Empty)
```

**Sysmon Event 1 — `whoami.exe` and payload PowerShell child:**
The payload process is tagged by the Sysmon ruleset as T1083 (File and Directory
Discovery) based on its command line content — demonstrating the sysmon-modular
config's coverage of this process pattern.

## What This Dataset Does Not Contain (and Why)

- **The elevated `notepad.exe` or `cmd.exe` executing.** No Sysmon Event 1 for
  `notepad.exe` appears and no Security 4688 for an elevated child is present, indicating
  the payload did not execute at high integrity. Defender's behavior monitoring blocked
  the auto-elevation chain.
- **`sdclt.exe` spawning an elevated child.** `sdclt.exe` was launched (Security 4688)
  but the elevated child is absent, consistent with Defender blocking the DelegateExecute
  callback.
- **Sysmon Event 11 (file creates) for payload artifacts.** The `sdclt` bypass does not
  drop files; only the PowerShell startup profile file appears in Event 11.

## Assessment

This dataset demonstrates the `sdclt.exe` variant of the DelegateExecute family of UAC
bypasses. The technique is distinct from the Fodhelper/ComputerDefaults variants in its
registry path (`Folder\shell\open\command` vs. `ms-settings\shell\open\command`).
Detection rules that check only `ms-settings` paths will miss this variant. The Sysmon
Event 13 and PowerShell 4104 logs provide clear evidence of the technique, with the
registry write to the `Folder` handler being the discriminating indicator.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Write to `*\Classes\Folder\shell\open\command\DelegateExecute`
  from a non-system process — rare outside of exploit activity.
- **PowerShell 4104:** Script block containing `Folder\shell\open\command`,
  `DelegateExecute`, and `Start-Process sdclt.exe` in the same block.
- **PowerShell 4103:** `New-ItemProperty` with `Name = DelegateExecute` on any
  `Classes\*\shell\open\command` path.
- **Security 4688:** `sdclt.exe` spawned by `powershell.exe` — `sdclt.exe` is
  legitimately invoked from the Windows Backup GUI; a `powershell.exe` parent is
  anomalous.
- **Sysmon Event 1:** `powershell.exe` child of `powershell.exe` with inline block
  referencing registry manipulation and `sdclt.exe`.
