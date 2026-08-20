# SPLUNK-Home-Lab-

## OVERVIEW 

This Splunk SOC home lab collects and analyzes Windows Security Event Logs using Splunk Enterprise and the Universal Forwarder. Custom SPL searches and 
dashboards monitor failed logins, privileged activity, account creation, and other security events, demonstrating hands-on SIEM, log analysis, 
detection, and security monitoring skills. This project documents the development of a Splunk-based SOC home lab designed to collect, analyze, and 
visualize Windows security events. The lab uses Splunk Enterprise as the SIEM and a Splunk Universal Forwarder to send Windows Event Logs from an 
endpoint to the Splunk server. The project focuses on detecting and investigating security events such as failed logins, successful logins, privileged 
logons, account creation, and other Windows security activity.


## HARDWARE: 

Splunk Receiver/Indexer: MacBook Air M1 2020 8GB 

Splunk Client/Forwarder: Windows 11 HP 

Splunk Client/Forwarder: Windows 10

Splunk Client/Forwarder: Windows 11 Surface Pro

## SET-UP/CONFIGURATION: 

Downloaded and installed Splunk Universal Forwarder on all three local windows machines. Although the heavy forwarder offer a wider range of 
capabilities with integrated data parsing and graphical interface, the universal forwarder is lightweight and less resource intensive.  In a different use case, 
handling sensitive data in transit within an enterprise level environment, a Splunk Heavy Forwarder is necessary. However, for basic logging and 
endpoint monitoring in a home lab local network scale, my set-up choice was ideal.


Configured the receiving tab on Mac to open port 9997 to accept connections from forwarders sending logs.

<img width="1181" height="246" alt="Screenshot 2026-08-19 at 5 55 36 PM" src="https://github.com/user-attachments/assets/de76f2c7-de23-40fe-a190-2f3c38f627a8" />

On two occasions with both the Windows 10 and the Windows 11 Surface Pro, I encountered an issue with the Splunk forwarders. Each restart 
attempt would display “Error 1053” and the raw event logs were unable to reach the Splunk indexer. 

Ultimately, I discovered that every time the assigned IP address of the Splunk receiver changed, the outputs.conf file wouldn’t update to the 
new address. I also found that my receiving host was connected to the wrong wifi network. To solve this problem, I reconnected to the shared 
network and edited the output file with the correct IP. 

<img width="934" height="361" alt="unnamed" src="https://github.com/user-attachments/assets/34cdb8af-4155-4a22-ac88-563583441eb5" />

## DASHBOARD 

Purpose: This dashboard visualizes Windows system and security event logs with graphs and statistic tables. The panels shown were derived from SPL queries, 
filtered to reduce noise and count real-time detections. The dashboard enhances alert visibility and monitoring by consolidating log results and facilitating 
analysis. The following panels include: Successful Logins, Privileged Logons, Top Failed Logons, Brute Forcing Detection, Total Successful vs Failed Logins

c

