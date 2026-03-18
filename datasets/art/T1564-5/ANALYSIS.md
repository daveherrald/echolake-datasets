# T1564-5: Hide Artifacts — Command Execution with NirCmd

## Technique Context

MITRE ATT&CK T1564 (Hide Artifacts) includes techniques that suppress visible UI elements to prevent users from noticing malicious activity. This test uses NirCmd — a legitimate, widely-distributed Windows command-line utility from NirSoft — to hide the system clock widget in the taskbar tray area:

```
nircmd.exe win child class "Shell_TrayWnd" hide class "TrayClockWClass"
```

NirCmd can control windows, processes, audio, network adapters, and registry entries through a simple command-line interface. It is frequently abused by malware and RATs because it allows UI manipulation without writing custom shellcode, and because many security tools do not alert on a signed, benign-seeming utility. This specific invocation hides a window class within the system tray, which could be used to prevent clock-based temporal awareness by a victim or to suppress other UI elements that might indicate compromise.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:19:41–14:19:46 UTC).

**Process execution chain (Sysmon EID 1 / Security EID 4688):**

The ART test framework launched PowerShell as SYSTEM, which spawned cmd.exe to invoke nircmd.exe:

```
"powershell.exe" & {cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\nircmd.exe" win child class "Shell_TrayWnd" hide class "TrayClockWClass"}
```

cmd.exe then executed:

```
"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\nircmd.exe win child class Shell_TrayWnd hide class TrayClockWClass
```

Both the PowerShell invocation (with quoted class names) and the cmd.exe invocation (without quotes) are captured with full command lines. The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\nircmd.exe` is visible verbatim, including the traversal component, which is a characteristic ART payload path.

**Notable absence in Sysmon:** `nircmd.exe` itself was not captured as a Sysmon EID 1 process create event. The sysmon-modular include-mode ProcessCreate configuration targets known LOLBins and specific suspicious patterns. NirCmd is not in that include list. Security EID 4688 similarly does not capture `nircmd.exe` because the Security log in this dataset captured only 12 events (4688/4689/4703) and `nircmd.exe` is not present among them — likely because command-line auditing did capture cmd.exe but the nircmd.exe child was processed after the capture window closed, or because NirCmd ran and exited too quickly. The process tree in Security confirms cmd.exe ran but stops there.

**Sysmon EID 7 (Image Load):** DLL loads for both PowerShell instances with T1055 and T1059.001 annotations.

**Sysmon EID 10 (Process Access):** PowerShell cross-process access to whoami.exe and cmd.exe with full access rights.

**PowerShell EID 4103:** `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` for both PowerShell instances.

**Security EID 4688:** whoami.exe, powershell.exe, and cmd.exe processes captured.

## What This Dataset Does Not Contain (and Why)

**No nircmd.exe process create event in Sysmon:** The sysmon-modular include-mode filter does not match NirCmd by name or by any of its behavioral characteristics. An exclude-mode configuration or a broader process creation rule would be required to capture it.

**No Security EID 4688 for nircmd.exe:** NirCmd appears not to have generated a Security process creation event within the captured window. This may be a timing artifact.

**No window manipulation or GUI events:** Windows does not generate security telemetry for `ShowWindow`/`HideWindow` API calls. The actual hiding of the clock widget produces no observable log entry.

**No file creation event for nircmd.exe:** The binary was already staged at `C:\AtomicRedTeam\ExternalPayloads\nircmd.exe` before the test window. No file download or write event is present.

## Assessment

The dataset demonstrates a meaningful detection gap: NirCmd's execution is visible only in the parent process chain (cmd.exe command line), not from a process creation event for nircmd.exe itself. This is a direct consequence of Sysmon's include-mode ProcessCreate filtering — a deliberate architectural choice that reduces volume but creates blind spots for unlisted binaries. The effect of the command (hiding a UI element) is entirely invisible in any log source.

The most actionable signal is the cmd.exe command line containing `nircmd.exe` with window-hiding arguments, which is present in both Sysmon EID 1 and Security EID 4688 for the cmd.exe process.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `cmd.exe` command line referencing `nircmd.exe` with `win child class ... hide class` arguments. The specific class name `Shell_TrayWnd` is a strong indicator.
- **Sysmon EID 1:** `powershell.exe` invoked as SYSTEM from `C:\Windows\TEMP\` wrapping a `cmd /c` invocation with a path under `C:\AtomicRedTeam\ExternalPayloads\` — the staging path is a consistent ART artifact.
- **File-based:** Detection of `nircmd.exe` at rest using hash or file name, particularly under `C:\AtomicRedTeam\ExternalPayloads\`. NirCmd's SHA256 is well-known; threat intelligence lookups on the binary can surface it regardless of process logging gaps.
- **Gap:** Without Sysmon EID 1 for the nircmd.exe process itself, parent-process chaining is required to attribute the execution. A Sysmon configuration that adds NirCmd to the include list, or switches to exclude-mode process creates, would close this gap.
