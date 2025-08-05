# Threat Event (Unauthorized Chrome-Based Surveillance)
**Stimulated Spyware Implant via Malicous Chrome Extension and C2 Activity**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Dropped a Suspicious Payload:
A simulated spyware JavaScript payload (monitor_payload.js) was dropped into Chrome's local user data directory to mimic browser surveillance behavior.
Path:
C:\Users\ybemployee\AppData\Local\Google\Chrome\User Data\monitor_payload.js
2. Simulated Manual Extension Installation:
A fake Chrome extension was created and manually loaded via Developer Mode at chrome://extensions. This action simulated abuse of Chrome’s extension APIs to monitor user activity.
3. Launched Chrome with Remote Debugging Port:
Chrome was started using the --remote-debugging-port=9222 flag to simulate command-and-control (C2)-style access via DevTools.
4. Connected to Simulated Beaconing Domain:
Multiple processes, including chrome.exe, powershell.exe, and svchost.exe, attempted outbound connections to the fake C2 domain:
suspicious-tracker-notreal.biz



## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect suspicious JS files and simulated surveillance logs. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect Chrome launched with suspicious flags.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect attempted connections to C2-like domains.|

---

## Related Queries:
```kql
// Detect dropped JS payload and simulated spyware log
DeviceFileEvents
| where FileName has_any("monitor_payload.js", "user_activity.log")
| where DeviceName == "chromebook"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType

// Detect Chrome launched with remote debugging (C2 behavior)
DeviceProcessEvents
| where ProcessCommandLine has "--remote-debugging-port"
| where DeviceName == "chromebook"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Detect simulated beaconing to malicious domain
DeviceNetworkEvents
| where RemoteUrl has "suspicious-tracker-notreal.biz"
| where DeviceName == "chromebook"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
```

---

## Created By:
- **Author Name**: Musie Berhe
- **Author Contact**:
- **Date**: August 5, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August  5, 2025`  | `Musie Berhe`   
