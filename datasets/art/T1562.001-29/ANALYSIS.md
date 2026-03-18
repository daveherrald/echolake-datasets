# T1562.001-29: Disable or Modify Tools — Kill antimalware protected processes using Backstab

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) covers adversary actions that prevent security software from running or reporting. Backstab is an open-source offensive tool that leverages the Windows Process Explorer driver (`procexp.sys`) to kill processes protected by Antimalware Protection Light (PPL). PPL is the kernel-level mechanism that prevents user-mode processes from opening handles to protected processes like `MsMpEng.exe` (Windows Defender). Backstab abuses the legitimate, Microsoft-signed driver to perform the termination, bypassing standard userland restrictions. This technique has been observed in the hands of ransomware operators and red teams seeking to blind endpoint detection before payload execution.

## What This Dataset Contains

The dataset captures 6 seconds of telemetry from ACME-WS02 (Windows 11 Enterprise Evaluation, domain member) during the Atomic Red Team execution of Backstab64.exe targeting `MsMpEng.exe`.

**Security 4688 — Process creation, test framework launches Backstab via PowerShell:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {& \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\Backstab64.exe\" -k -n MsMpEng.exe}
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**PowerShell 4104 — Script block logging captures the invocation verbatim:**
```
& {& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Backstab64.exe" -k -n MsMpEng.exe}
```

**Sysmon EID 7 — Image loads into the PowerShell process context:**
Multiple DLLs tagged with technique rules `T1055/Process Injection` and `T1574.002/DLL Side-Loading` load into the PowerShell process. Windows Defender client libraries `MpClient.dll` and `MpOAV.dll` are among the images loaded, consistent with AMSI and Defender integration. The .NET CLR (`clr.dll`, `clrjit.dll`, `mscoreei.dll`) loads are standard test framework overhead.

**Sysmon EID 10 — Process access events:**
Two events tagged `T1055.001/Dynamic-link Library Injection` show PowerShell (PID 2248) accessing `whoami.exe` and a child `powershell.exe` with `GrantedAccess: 0x1FFFFF` (full access). This is framework-generated overhead from the ART framework monitoring child processes.

**Sysmon EID 1 — Process creates visible to Sysmon:**
`whoami.exe` (ART identity check) and the child `powershell.exe` launching Backstab appear as Sysmon process create events. Backstab64.exe itself does **not** appear as an EID 1 process create — Defender prevented it from executing as a standalone process before the Windows security subsystem registered the creation.

**Application EID 16384 and TaskScheduler EID 140:**
Software Protection Platform (`sppsvc.exe`) activity, unrelated to the test — background OS noise captured within the time window.

## What This Dataset Does Not Contain (and Why)

**Backstab64.exe as a process create event** — Backstab64.exe never appears in Security 4688 or Sysmon EID 1 with its own image path. Windows Defender blocked the binary before process creation was recorded. The only visible trace is the parent PowerShell's command line containing the path to the executable.

**Driver load event for `procexp.sys`** — Backstab's kill mechanism relies on loading the Process Explorer driver. No Sysmon EID 6 (driver load) appears because the attack was stopped before the driver load stage.

**Registry modification for driver service registration** — Backstab typically writes a service key to load the driver. No Sysmon EID 13 matching this path is present.

**MsMpEng.exe termination** — The Defender process was not killed. The dataset shows no EID 4689 exit event for `MsMpEng.exe`.

**0xC0000022 access denied** — While Defender-protected processes generate access denied status codes when termination is attempted, this dataset does not contain such a code. Defender intervened at the binary execution stage before any handle was opened to a protected process.

## Assessment

This is a **blocked execution** dataset. Defender stopped Backstab64.exe before it ran. The telemetry value is in the attempt signature: the command line `Backstab64.exe -k -n MsMpEng.exe` appears verbatim in both Security 4688 (process command line of the parent PowerShell) and PowerShell 4104 (script block). The Sysmon include-mode configuration did not capture Backstab64.exe as a process create because the binary's path does not match any Sysmon include rules, and Defender prevented execution before auditing recorded it. Security 4688 captured the parent PowerShell's launch command, which contains the full Backstab invocation, making this dataset useful for command-line detection even though the payload never fully executed.

## Detection Opportunities Present in This Data

- **Command line matching** (Security 4688 / Sysmon EID 1): The string `Backstab` or `Backstab64.exe` in `powershell.exe` command line arguments is a strong indicator. The `-k -n MsMpEng.exe` flag pattern should also be detectable.
- **PowerShell script block** (EID 4104): The script block `& "...\Backstab64.exe" -k -n MsMpEng.exe` is logged in full. Any SIEM pipeline processing 4104 will receive this string in plaintext.
- **Path traversal in binary reference**: The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` is an unusual pattern that combines a known red team tool directory with directory traversal. This pattern may be useful for tuning.
- **Image load of Defender internals by non-Defender process**: `MpClient.dll` and `MpOAV.dll` loading into `powershell.exe` (EID 7) may indicate AMSI-related activity worth correlating against unexpected script execution.
