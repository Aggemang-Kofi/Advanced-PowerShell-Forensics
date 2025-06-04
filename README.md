# Advanced Windows Forensics and Incident Response Using PowerShell

## Introduction

PowerShell is a robust and scriptable command-line interface integrated into Windows that enables in-depth system investigation and rapid incident response. This lab provides advanced practitioners with a comprehensive framework for performing forensic tasks on compromised or suspicious Windows hosts. You’ll leverage PowerShell to enumerate and correlate forensic artifacts, analyze behaviors, detect anomalies, and extract relevant data in a scalable, scriptable manner.

## Pre-requisites

* Proficient understanding of Windows internals (kernel, user-mode architecture, registry, services)
* Knowledge of common attack vectors and persistence techniques
* Experience with PowerShell scripting and automation
* Familiarity with MITRE ATT\&CK, DFIR methodologies, and Windows Event Logging

## Lab Environment

* Windows 10/11 or Windows Server 2016+
* PowerShell 5.1+ or PowerShell 7.x
* Local Administrator access or SYSTEM-level privileges recommended
* Tools for extended analysis (e.g., Sysinternals, Windows Event Forwarding optional)

## Advanced Lab Exercises

###  User Account Enumeration & Anomaly Detection

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordNeverExpires
Get-LocalGroupMember -Group 'Administrators'
reg query HKLM\SAM\SAM\Domains\Account\Users /s
```

> Analysis Tip: Look for recently created privileged accounts or accounts with anomalous last logon times.

###  Process Enumeration and Parent-Child Chain Reconstruction

```powershell
Get-CimInstance Win32_Process | Select Name, ProcessId, ParentProcessId, CreationDate, CommandLine | Sort-Object CreationDate
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq 4 }
```

> Watch for: Orphaned processes, unknown parent-child relationships (e.g., explorer.exe spawning powershell.exe).

### Service Analysis with Persistence Indicators

```powershell
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -ne "Running" } | Select Name, PathName, StartName, Description
Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*cmd.exe*" -or $_.PathName -like "*.ps1*" }
```

### . Scheduled Task Forensics

```powershell
Get-ScheduledTask | Select TaskName, TaskPath, State
Get-ScheduledTask | ForEach-Object {
    [PSCustomObject]@{
        Name     = $_.TaskName
        Action   = ($_.Actions | ForEach-Object {$_.Execute})
        Trigger  = ($_.Triggers | ForEach-Object {$_.StartBoundary})
    }
}
```

### Registry Startup & Persistence Hunting

```powershell
$paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $paths) {
    Get-ItemProperty -Path $path | Select-Object PSChildName, *
}
```

> Bonus: Hunt for suspicious entries in Image File Execution Options, AppInit\_DLLs, and Shell.

### Live Network Connection Analysis

```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } |
    Select-Object LocalAddress, RemoteAddress, RemotePort, State, @{Name="ProcName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
Get-NetTCPConnection | Where-Object { ($_ | Select-String -Pattern "^(?!10\\.|172\\.1[6-9]|172\\.2[0-9]|172\\.3[01]|192\\.168)") }
```

### . File Share Access and Remote Connections

```powershell
Get-SmbShare | Where-Object { $_.Name -ne "IPC$" }
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
```

### File System Timeline Analysis

```powershell
Get-ChildItem -Path C:\Users -Include *.exe, *.ps1, *.bat -Recurse -ErrorAction SilentlyContinue |
Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
Select Name, FullName, LastWriteTime
```

### Firewall & Rule Analysis

```powershell
Get-NetFirewallRule | Where-Object { $_.Direction -eq "Inbound" -and $_.Enabled -eq "True" } |
Select DisplayName, Action, Profile, Direction, Program
Get-NetFirewallProfile | Format-List Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### Session and Remote Access Discovery

```powershell
Get-SmbMapping
query user
```

### Log Analysis via Get-WinEvent

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" |
Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="Source IP";Expression={$_.Properties[18].Value}}
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=7045)]]"
```

> Use Get-WinEvent over Get-EventLog for performance and filtering on modern systems.


### Memory Resident Artifact Hunting (In-Memory Execution Detection)

```powershell
Get-WmiObject Win32_Process |
Where-Object { $_.CommandLine -match "Invoke-Expression|IEX|FromBase64String" } |
Select ProcessId, Name, CommandLine
```

> **Why it matters**: Attackers often use in-memory execution to avoid touching disk (e.g., PowerShell Empire, Cobalt Strike). Look for encoded, obfuscated, or base64-encoded payloads.

---

### Detecting Living-off-the-Land Binaries (LOLBins)

```powershell
Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match "rundll32|regsvr32|mshta|certutil|wmic|bitsadmin|scriptrunner"
} | Select Name, ProcessId, CommandLine
```

> **Detection Tip**: LOLBins are legitimate binaries abused for malicious purposes. Correlate these findings with suspicious command-line arguments or execution chains.

---

### Credential Dumping & LSASS Access Checks

```powershell
Get-Process -Name lsass | ForEach-Object {
    Get-ProcessMitigation -Id $_.Id
}
```

> Also review process handles and injected modules if tools like Mimikatz or procdump were used:

```powershell
Get-Process -Id (Get-Process lsass).Id | Select-Object Modules
```

---

### Lateral Movement and Remote Logon Detection

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" |
Where-Object { $_.Properties[8].Value -eq "10" } |  # Logon Type 10 = RDP
Select TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="SourceIP";Expression={$_.Properties[18].Value}}
```

> **Correlate** with Event ID 4776 (NTLM authentication), 4672 (special privileges assigned), and 7045 (service installation).

---

### Deep DLL Persistence & COM Hijacking Inspection

```powershell
Get-ItemProperty -Path "HKCU:\Software\Classes\CLSID\*" -ErrorAction SilentlyContinue |
Where-Object { $_.InprocServer32 -like "*.dll" } | Select PSChildName, InprocServer32
```

> **Bonus**: Check known hijackable COM objects and track down suspicious DLLs in non-standard directories (e.g., user-writable paths).

---

###  Anomalous Binary Detection (Outlier Hashing + Source Verification)

```powershell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.exe, *.dll -ErrorAction SilentlyContinue |
ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    [PSCustomObject]@{
        Name = $_.Name
        Path = $_.FullName
        SHA256 = $hash.Hash
        Signed = (Get-AuthenticodeSignature $_.FullName).Status
    }
} | Where-Object { $_.Signed -ne "Valid" }
```

> Integrate with VirusTotal, HybridAnalysis, or internal threat intel for reputation checking.

---

###  Cross-Artifact Timeline Reconstruction

Combine timestamps across:

* Event logs (e.g., 4688: process creation, 7045: service install)
* `$MFT` entries (via `MFTECmd.exe`)
* Registry hives (e.g., LastWrite time of Run keys, USB history)
* Shimcache and Amcache (requires external parsers)

This creates an attacker activity timeline:

```plaintext
[08:01] 4688 - powershell.exe spawned
[08:02] MFT - new .ps1 script created in AppData
[08:03] Registry - Run key updated
[08:04] 7045 - service created
```

---

###  MITRE ATT\&CK Mapping Reference (Optional Output)

Consider tagging findings to MITRE ATT\&CK techniques:

| Activity                    | Technique ID | Name                                             |
| --------------------------- | ------------ | ------------------------------------------------ |
| New user in Admins group    | T1136.001    | Create Account: Local Account                    |
| PowerShell with Base64      | T1059.001    | Command & Scripting: PowerShell                  |
| Auto-start registry key     | T1547.001    | Boot or Logon Autostart: Registry                |
| Suspicious service creation | T1543.003    | Create or Modify System Process: Windows Service |
| Outbound to public IPs      | T1071        | Application Layer Protocol                       |

---

###  Incident Response Automation Framework (Snippet)

Kick-start automated triage with a modular PowerShell function:

```powershell
function Invoke-IRSweep {
    Write-Host "[*] Enumerating suspicious users..."
    Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.LastLogon -gt (Get-Date).AddDays(-1) }

    Write-Host "[*] Checking scheduled tasks..."
    Get-ScheduledTask | Where-Object { $_.TaskPath -like "*Microsoft\Windows\*" -eq $false }

    Write-Host "[*] Listing suspicious processes..."
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "invoke|iex|mshta|certutil" }
}
```

> Expand this into a full PowerShell module with alerting, JSON export, or CSV integration for reporting.


