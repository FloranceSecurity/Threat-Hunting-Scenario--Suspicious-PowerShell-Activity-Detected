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



