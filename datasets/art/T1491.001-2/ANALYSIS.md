# T1491.001-2: Internal Defacement — LegalNoticeCaption and LegalNoticeText Ransom Message

## Technique Context

T1491.001 (Internal Defacement) covers adversary modifications to systems intended to intimidate users or signal a compromise. Setting the Windows Legal Notice caption and body text via registry is a technique commonly observed in ransomware operations where operators want every user who logs into a machine to immediately see the ransom message. Unlike wallpaper replacement, this technique modifies the login screen notification — visible before any user authenticates — making it particularly effective for organizational impact. The registry keys `LegalNoticeCaption` and `LegalNoticeText` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` control the dialog shown at logon and are well-known to ransomware operators (PYSA/Mespinoza is named directly in this test's ransom message text).

## What This Dataset Contains

The execution is carried out by an inline PowerShell script captured fully in both Security Event ID 4688 and Sysmon Event ID 1. The command sets two registry values:

```
powershell.exe & {
  $newLegalNoticeCaption = "PYSA"
  $newLegalNoticeText = "Hi Company, every byte on any types of your devices was encrypted.
    Don't try to use backups because it were encrypted too.
    To get all your data contact us:xxxx@onionmail.org"
  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    -Name LegalNoticeCaption -Value $newLegalNoticeCaption -Type String -Force
  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    -Name LegalNoticeText -Value $newLegalNoticeText -Type String -Force
}
```

Critically, this dataset contains **Sysmon Event ID 13 (RegistryValue Set)** — the only dataset in this set that captures the actual registry write event alongside the process creation evidence. Two Event ID 13 records show:

- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption` with `Details: PYSA`
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText` with `Details: Hi Company, every byte on any types of your devices was encrypted...`

The image performing the write is `powershell.exe`. The PowerShell/Operational channel captures the full script as a 4104 script block log entry — unlike most other tests in this collection where the PowerShell channel contains only boilerplate — because `Set-ItemProperty` is invoked as cmdlet (module logging captures the full block).

## What This Dataset Does Not Contain

- **No secondary process creation**: The technique is executed entirely via PowerShell cmdlets (`Set-ItemProperty`) without spawning child processes, so there is no `reg.exe` process chain to correlate against.
- **No network activity**: This is a purely local registry modification; no external communication is required or present.
- **No audit policy registry object access events**: The `object_access` audit policy is set to `none`, so no Security 4657 (Registry Value Modified) events are generated. Security 4688/4689 cover only process lifecycle.

## Assessment

This is one of the strongest datasets in this collection. It provides layered, corroborating evidence across three channels: the PowerShell script block (4104) containing the exact ransom message text and the `Set-ItemProperty` call, the process creation event with the full command line, and the Sysmon registry write events (Event ID 13) showing the exact key paths and written values. The ransom message text in both the command line and the `Details` field of the Sysmon registry event is a high-fidelity detection indicator. This dataset is well-suited for training detection rules at both the process and registry event levels. The only meaningful gap is the absence of Security 4657 registry modification events, which would require enabling Object Access auditing.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 targeting `LegalNoticeCaption` or `LegalNoticeText`** — Direct registry write evidence showing the exact ransom message in the `Details` field; extremely high-confidence indicator.
2. **`powershell.exe` command line or script block containing `LegalNoticeCaption` or `LegalNoticeText` with `Set-ItemProperty`** — Visible in Security 4688, Sysmon Event ID 1, and PowerShell 4104; any one channel is sufficient for a rule.
3. **`Set-ItemProperty` on `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` by SYSTEM-context PowerShell** — Module logging (4103) or script block logging (4104) in the PowerShell channel captures this cmdlet invocation.
4. **Registry path `Policies\System\LegalNoticeText` being written with non-empty, high-entropy string content** — The presence of readable ransom note text in the `Details` field allows keyword-matching detections (e.g., matching on "encrypted", "contact us", or specific ransomware actor names).
5. **Inline PowerShell script block logging capturing ransom actor name strings** — PowerShell 4104 preserves the full script including `"PYSA"` and the contact email, enabling actor-tracking detections tied to specific ransomware families.
