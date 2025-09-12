# Suspicious PowerShell Activity Detected: Attempted Malicious File Download and Execution
## Platforms and Languages Leveraged
* Windows Operating System
* Microsoft Defender for Endpoint
* PowerShell (Scripting Language)
* KQL (Kusto Query Language)
## Scenerio
During security monitoring, a series of suspicious PowerShell executions were detected on a Windows device called arya-vm-onboard. The PowerShell process was launched with command line arguments linked to malicious behavior. It attempted to bypass script execution policies and run scripts in hidden windows.

The attacker also used PowerShell to make web requests, trying to download an executable from a local web server and then launch it. These actions are typical of malware delivery attempts.

The activity shows signs of both automation and evasion, which can create a serious risk if not addressed quickly. Advanced hunting and event analysis in Microsoft Defender exposed these attempts in detail, which allowed for a rapid response and containment of the threat.
## High-Level PowerShell-Related IoC Discovery Plan
* Check `DeviceProcessEvents` for any `powershell.exe` process creation events with suspicious command-line arguments `(e.g., DownloadFile, WebClient, -ExecutionPolicy Bypass, -WindowStyle Hidden, http, or https)`.
* Check `DeviceNetworkEvents` for any signs of outgoing connections initiated by `powershell.exe`, especially to unknown or unusual remote IPs and URLs.
* Check `DeviceFileEvents` for any file creation or downloads performed by `powershell.exe` in non-standard or suspicious locations.
## Hunting Suspicious PowerShell Activity
```DeviceProcessEvents
| where DeviceName startswith "ARYA"
| where FileName == "powershell.exe"
| order by Timestamp desc
| where AccountName !in ("system", "local service")
| where ProcessCommandLine has_any ("DownloadFile", "DownloadData", "DownloadString", "WebClient", "WebRequest", "http", "https", "-ExecutionPolicy", "-WindowStyle Hidden", "Bypass")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256```
<img width="1383" height="698" alt="image" src="https://github.com/user-attachments/assets/f67b1db0-b72d-43f1-807d-078ab3e6c292" />





