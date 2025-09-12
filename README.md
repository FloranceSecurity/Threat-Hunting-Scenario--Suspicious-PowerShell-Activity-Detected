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
## Step 1: Hunting Suspicious PowerShell Activity
```
DeviceProcessEvents
| where DeviceName startswith "ARYA"
| where FileName == "powershell.exe"
| order by Timestamp desc
```
The query begins by pulling data from the `DeviceProcessEvents` table. This table logs every process that starts on endpoints protected by Microsoft Defender for Endpoint. It provides a detailed view of program execution across devices.

The scope is then narrowed to devices whose names start with `ARYA, such as ARYA01 or ARYA-VM`. This ensures the investigation is focused on a specific machine or group of machines. From there, the results are filtered further to include only entries where the process name is `powershell.exe`, highlighting PowerShell activity on the selected devices.

The output is sorted so that the most recent events appear first. This approach allows faster review of the latest suspicious activity without sifting through older data.

<img width="1469" height="615" alt="image" src="https://github.com/user-attachments/assets/0e018edb-4f50-4cde-becd-8ee50715f174" />

## Step 2: Query Exluded Built-in Service Accounts
```
DeviceProcessEvents
| where DeviceName startswith "ARYA"
| where FileName == "powershell.exe"
| order by Timestamp desc
| where AccountName !in ("system", "local service")
```
To minimize noise, the query excludes events triggered by built-in service accounts like `System and Local Service`. This keeps the results centered on actions performed by real users or potential attackers.

<img width="1511" height="342" alt="image" src="https://github.com/user-attachments/assets/85c0ee8a-429a-486e-a6f2-5eb0ec851ebb" />

## Step 3: Filtering for PowerShell Command-line Arguments
```
DeviceProcessEvents
| where DeviceName startswith "ARYA"
| where FileName == "powershell.exe"
| order by Timestamp desc
| where AccountName !in ("system", "local service")
| where ProcessCommandLine has_any ("DownloadFile", "DownloadData", "DownloadString", "WebClient", "WebRequest", "http", "https", "-ExecutionPolicy", "-WindowStyle Hidden", "Bypass")
```
Another layer of filtering looks for `PowerShell command-line arguments` often associated with malicious behavior. These include commands designed to `download files, bypass execution policies, or hide execution windows`. Such patterns are strong indicators of automated or malicious activity.

<img width="1498" height="364" alt="image" src="https://github.com/user-attachments/assets/dcd14d29-a847-4773-8409-fa0cb3009083" />

## Step 4: Displaying most relavant column
```
DeviceProcessEvents
| where DeviceName startswith "ARYA"
| where FileName == "powershell.exe"
| order by Timestamp desc
| where AccountName !in ("system", "local service")
| where ProcessCommandLine has_any ("DownloadFile", "DownloadData", "DownloadString", "WebClient", "WebRequest", "http", "https", "-ExecutionPolicy", "-WindowStyle Hidden", "Bypass")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
```

Finally, the query selects and displays only the most relevant columns for investigation. These include event time, device details, process name, full command line, user information, parent process data, folder path, and file hash. Together, this set of fields provides the context needed to analyze and confirm suspicious PowerShell activity.

<img width="1491" height="373" alt="image" src="https://github.com/user-attachments/assets/f320c9b6-3adc-4660-bbdb-f225d4d7b0fe" />






