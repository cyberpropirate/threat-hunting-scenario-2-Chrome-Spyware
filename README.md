# threat-hunting-scenario-2-Chrome-Spyware
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="250" height="250" alt="image" src="https://github.com/user-attachments/assets/9c5c906d-31bb-4e3c-97c7-ca14c4c9c57e" />


# Threat Hunt Report: Unauthorized Chrome Based Surveillance
- [Scenario Creation](https://github.com/cyberpropirate/threat-hunting-scenario-2-Chrome-Spyware/blob/main/threat-hunting-scenario-spyware-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Google Chrome Browser

##  Scenario

The threat hunt was initiated in response to a simulated real-world incident similar to a cybersecurity job post involving suspected spyware activity on personal devices. The goal was to simulate and investigate browser-based surveillance using a malicious Chrome extension and command-and-control (C2)-like behavior.

### High-Level Spyware-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `dropped payloads (.ps1, .js)` and stimulated spyware logs.
- **Check `DeviceProcessEvents`** to detect Chrome for any suspicious flags or script executions.
- **Check `DeviceNetworkEvents`**  to detect connections to suspicious external domains (C2 simulation).

--

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Detect evidence of suspicious JavaScript or log files dropped on the machine by the stimulated attacker. Searched for filenames related to `monitor_payload.js` At `2025-08-05T00:21:06.9827419Z` the file `monitor_payload.js` was created. Indicates unauthorized file creation related to spyware-like behavior.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName has_any("monitor_payload.js", "user_activity.log")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType
| order by Timestamp desc
| where DeviceName == "chromebook"

```
<img width="2408" height="1441" alt="{AA79E9B7-C2E7-47D5-BD04-63008707BFF3}" src="https://github.com/user-attachments/assets/36aebe71-8209-4dad-9d04-2681bf42a9b8" />


---

### 2. Searched the `DeviceProcessEvents` Table

Detect Chrome being launched with suspicious flags  `--remote-debugging-port` common technique to stimulate C2 capabilities. Looked for any process command lines containing the `–remote-debugging-port` flag. At `2025-08-05T00:31:34.1364655Z`, Chrome was launched using this powershell command `"chrome.exe" --remote-debugging-port=9222 https://suspicious-tracker-notreal.biz`. This command was executed by user ybemployee, suggesting unauthorized use of DevTools debugging to enable C2-like access to Chrome’s internals.   


**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine has "--remote-debugging-port"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
| where DeviceName == "chromebook"

```
<img width="2407" height="1389" alt="{4FE0D671-0A08-4172-BB17-654B07DFDFCE}" src="https://github.com/user-attachments/assets/a3e6e682-853e-4277-bd03-19e906f7fd95" />


---

### 3. Searched the `DeviceNetworkEvents` Table 

  Identify any attempted beaconing to known C2 or suspicious domains. Searched for connections to `suspicious-tracker-notreal.biz`, the stimulated malicious beaconing domain. At `2025-08-05T00:52:06.8036917Z`, the process chrome.exe attempted to access the URL using a suspicious command line: `"chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --metrics-shmem-handle=1604,i,9752546010034232807,1536234990615310459,524288 --field-trial-handle=1936,i,15777318982512432632,10974513789961801933,262144 --variations-seed-version=20250804-050057.034000 --mojo-platform-channel-handle=2264 /prefetch:3`. At `2025-08-05T01:03:04.2860323Z`, `powershell.exe` attempted to reach the same URL suggesting potential use of script based C2 simulation. At ` 2025-08-05T01:14:46.9255943Z`, `svchost.exe` also initiated a connection. This may represent either background Windows behaviour or further simulation noise. All three events attempt to initiate outbound connections to the domain `suspicious-tracker-notreal.biz`

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where RemoteUrl has "suspicious-tracker-notreal.biz"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp desc
| where DeviceName == "chromebook"

```
<img width="2329" height="1385" alt="{2F31B85B-B8C7-462D-98AC-18167D0030DF}" src="https://github.com/user-attachments/assets/9894c0ff-a762-48d1-9012-dc33c6e97fbc" />

---





## Chronological Event Timeline 

### 1. File Creation – Spyware Payload Dropped


- **Timestamp:** `2025-08-05T00:21:06.9827419Z`
- **Event:**  A suspicious JavaScript file named `monitor_payload.js ` was created in Chrome’s user data directory. This file simulates spyware behavior, such as browser telemetry or tab monitoring.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ybemployee\AppData\Local\Google\Chrome\User Data\monitor_payload.js
`

### 2. Process Execution - Chrome Launched with Remote Debugging Port


- **Timestamp:** `2025-08-05T00:31:34.1364655Z`
- **Event:** Chrome was executed using the `--remote-debugging-port=9222` flag, a common method for gaining DevTools-level access to browser internals, often abused by spyware or surveillance malware.
- **Action:** Process creation detected.
- **Command:** `"chrome.exe" --remote-debugging-port=9222 https://suspicious-tracker-notreal.biz`
- **File Path:** `C:\Program Files\Google\Chrome\Application\chrome.exe`

### 3. Network Connection – Simulated C2 Beacon via Chrome

- **Timestamp:** `2025-08-05T00:52:06.8036917Z`
- **Event:** Chrome attempted to access a simulated malicious domain `suspicious-tracker-notreal.biz`, mimicking command-and-control (C2) activity.
- **Action:** Outbound network connection detected.
- **Command Line:** `chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService …`
- **Remote IP:** 93.184.216.34
- **Remote URL:** suspicious-tracker-notreal.biz
- **File Path:** `c:\program files\google\chrome\application\chrome.exe`

### 4. Network Connection – PowerShell Beacon Attempt


- **Timestamp:** `2025-08-05T01:03:04.2860323Z`
- **Event:** `powershell.exe` made a simulated outbound request to the same domain. This behavior is consistent with script-based data exfiltration or command execution.
- **Action:** Outbound network connection detected.
- **Process:** `powershell.exe`
- **Remote IP:** 93.184.216.34
- **Remote URL:** suspicious-tracker-notreal.biz
- **File Path:** `c:\windows\system32\windowspowershell\v1.0\powershell.exe`

### 5. Network Connection – Background Activity via svchost.exe


- **Timestamp:** `2025-08-05T01:14:46.9255943Z` 
- **Event:** `svchost.exe`  attempted to connect to the same suspicious domain. While this could indicate system-level behavior, in a lab context, it may represent simulation noise or inherited traffic redirection.
- **Action:** Outbound network connection detected.
- **Remote IP:** 93.184.216.34
- **Remote URL:** suspicious-tracker-notreal.biz
- **File Path:** c:\windows\system32\svchost.exe


---

## Summary

The threat hunt was initiated in response to a simulated real-world incident similar to a cybersecurity job post involving suspected spyware activity on personal devices. The goal was to simulate and investigate browser-based surveillance using a malicious Chrome extension and command-and-control (C2)-like behavior.
The user "ybemployee" on the "chromebook" device created a simulated surveillance payload named `monitor_payload.js` in Chrome’s user data directory. Shortly after, Chrome was launched using the `--remote-debugging-port=9222` flag, a known technique to enable DevTools-based remote access often abused by attackers. This simulated a C2 channel. Multiple outbound connection attempts were made to a fake beaconing domain `suspicious-tracker-notreal.biz` by `chrome.exe`, `powershell.exe`, and `svchost.exe`, emulating persistence and data exfiltration behaviors.
The sequence of activities effectively reproduced indicators of compromise (IoCs) associated with browser-based spyware and provided telemetry in Defender XDR for detection and hunting practice.


---

## Response Taken

Unauthorized browser surveillance activity was confirmed on the chromebook endpoint by the user ybemployee. The device was isolated, and the simulated malicious Chrome extension was removed. A detailed incident report was generated, and internal security leadership was notified for further review and escalation. Defender XDR alerts were created for continued monitoring of similar behavior across the environment.


---
