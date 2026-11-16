# Incident Response Report: Suspicious Outbound Traffic

**Ticket Number:** #9901
**Endpoint:** `DESKTOP-HR404`
**Lead Analyst:** Mutiyat Akinola
**Status:** Resolved

## Executive Summary

An alert was triggered for unusually high outbound network traffic on endpoint `DESKTOP-HR404`. The user reported downloading a candidate's resume (PDF) prior to the spike in system resource usage. The investigation revealed a malicious executable masquerading as a PDF update attempting to communicate with an external server over an unencrypted channel. The threat was successfully identified, quarantined via firewall rules, and its registry persistence was neutralized.

## 1. Network & DNS Investigation

To determine if the endpoint was communicating with unauthorized external infrastructure in the background, the local DNS resolver cache was queried.

**Command Executed:**
```cmd
ipconfig /displaydns

Finding: A highly suspicious DNS query was found for secure-pdf-update.ru resolving to IP address 198.51.100.77.

Active network connections were then filtered to identify which local process was maintaining an established connection with this malicious IP.

Command Executed:

netstat -ano | findstr ESTABLISHED
Finding: The connection to 198.51.100.77 was actively held open on Port 80 (HTTP) by Process ID (PID) 4128. The use of Port 80 indicates the malware was transmitting data in plain text without TLS encryption.

2. Process & File Identification
With the malicious PID identified, the task list was queried to unmask the executable's image name.

Command Executed:

tasklist /svc /fi "pid eq 4128"
Finding: PID 4128 was associated with the image name pdf_update.exe.

To safely quarantine the file, Windows Management Instrumentation (WMI) was used to locate the executable's true physical path on the disk.

Command Executed:

wmic process where "name='pdf_update.exe'" get ExecutablePath
Finding: The malware was executing from a non-standard directory: C:\Users\Public\Downloads\pdf_update.exe.

3. Remediation & Eradication
Network Quarantine:
An Outbound Program Rule was immediately created in the Windows Defender Firewall targeting C:\Users\Public\Downloads\pdf_update.exe. This explicitly blocked the malware from communicating over the network while allowing legitimate web browsers to continue functioning.

Persistence Cleanup:
The Windows Registry was queried to determine if the malware had established persistence to survive a system reboot.

Command Executed:

reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Finding: A malicious startup value named AdobeUpdate was discovered pointing to the malware's executable path.

The persistence mechanism was permanently deleted using the following command:

Command Executed:

reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "AdobeUpdate" /f
Conclusion
The malicious executable pdf_update.exe has been fully neutralized. Network communications have been blocked and reboot persistence has been eradicated. The endpoint is safe to return to normal operations.
