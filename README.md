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


## Initial Set-up Troubleshooting:

On two occasions with both the Windows 10 and the Windows 11 Surface Pro, I encountered an issue with the Splunk forwarders. Each restart 
attempt would display “Error 1053” and the raw event logs were unable to reach the Splunk indexer. 

Ultimately, I discovered that every time the assigned IP address of the Splunk receiver changed, the outputs.conf file wouldn’t update to the 
new address. I also found that my receiving host was connected to the wrong wifi network. To solve this problem, I reconnected to the shared 
network and edited the output file with the correct IP. 

<img width="934" height="361" alt="unnamed" src="https://github.com/user-attachments/assets/34cdb8af-4155-4a22-ac88-563583441eb5" />

## DASHBOARD 

Purpose: This dashboard visualizes Windows system and security event logs with graphs and statistic tables. The panels shown were derived from SPL queries, 
filtered to reduce noise and count real-time detections. The SOC dashboard was designed to enhance alert visibility and monitoring by consolidating log results and facilitating 
analysis. The following panels include: Successful Logins, Privileged Logons, Top Failed Logons, Brute Forcing Detection, Total Successful vs Failed Logins


## PANEL 1: Successful Logons By Account - Past 30 Days

Overview: 


## Problems: 


During dashboard validation, duplicate-looking Windows Event ID 4624 records caused successful logon counts to become inflated. The other major issue was noisy background 
detection caused by two Windows services, Desktop Window Manager (DWM) and User Mode Font Driver (UMFD). Both of which created local interactive sessions that counted higher results 
without differentiating between display system behavior and human interacted logins.

----------------

To reduce the detection noise, I filtered the DWM and UMFD logons using the following command:

| where NOT match(all_account_values_joined,"(^|\\|)(DWM-[0-9]+|UMFD-[0-9]+)(\\||$)"). 

-----------------


To address the deduplication, I filtered for the EventRecordID and raw-event hashes:

| eval raw_hash=md5(_raw)
| eval unique_event=coalesce(record_id, raw_hash)
| dedup host unique_event


---------

My initial attempt was effective in removing the DWM and UMFD logs. However, the duplicated logs still remained after filtering. because the records differed internally despite 
representing the same visible login activity. 


<img width="786" height="566" alt="Screenshot 2026-08-20 at 10 35 56 AM" src="https://github.com/user-attachments/assets/9776f0ed-5514-4bb2-aab0-3fffbcaa8480" />

--------



<img width="912" height="393" alt="Screenshot 2026-08-20 at 11 24 52 AM" src="https://github.com/user-attachments/assets/198c9567-9ea9-4997-8b24-d62a9bbacc2f" />

----------


## Solution: 

During my troubleshoot, I discovered the records differed internally despite representing the same visible login activity. To solve this, I further fine tuned the detection logic by 
normalizing multi-value account fields, filtering background accounts and deduplicating events using timestamp instead of the md5 hashes. By combining these techniques, it allowed 
me to produce a more accurate representation of real interactive user authentication activity.

Final SPL Search:

| dedup _time host logon_account logon_type
| stats count as successful_logons by host logon_account
| sort host - successful_logons

______________

<img width="794" height="504" alt="Screenshot 2026-08-20 at 11 33 34 AM" src="https://github.com/user-attachments/assets/ffc21149-b59e-43fd-9460-ca991f123098" />

_________


<img width="1192" height="143" alt="Screenshot 2026-08-20 at 12 18 18 PM" src="https://github.com/user-attachments/assets/19d3f1bb-ebc1-4bd2-a97f-9bd53f247749" />


____

## PANEL 2: PRILVILEGED LOGONS BY ACCOUNT - PAST 30 DAYS 

This panel was appended to the SPLUNK dashboard to track access on privileged accounts. This is can be very helpful for catching potential threats by using timestamps to capture when the account logon occurred and determining their access to data.

Problems:

In comparison to the previous panel, I consolidated the fields and filtered the noise from background system processes. I performed both these functions using the eval command. I didn't encounter difficulty in my initial attempt. 

___

<img width="1017" height="402" alt="Screenshot 2026-08-29 at 1 13 53 PM" src="https://github.com/user-attachments/assets/abf09106-adee-4f6a-8558-bad916fc348b" />

___

For the data visualization I selected the bar graph. Its presentation offers the clearest view of the highest instances of privileged logons and included interaction that reveals the events associated with each account. 

___

<img width="698" height="281" alt="Screenshot 2026-08-29 at 1 22 46 PM" src="https://github.com/user-attachments/assets/397a78f4-d396-4e0f-aa16-68ec8ed5a981" />

___

## PANEL 3: FAILED LOGONS - PAST 30 DAYS 


Overview:

This SPL query identifies and counts failed Windows logon attempts (4625). It filters out invalid, empty, and Guest account values, then checks multiple possible username fields to determine which account experienced the failed login. The query cleans and standardizes the account name, removes anonymous or unusable entries, and counts the total number of failed authentication attempts for each account. The results are sorted from the account with the most failed logins to the least, helping identify accounts that may be experiencing repeated authentication failures or potential brute-force activity.


____

<img width="660" height="247" alt="Screenshot 2026-08-29 at 1 38 13 PM" src="https://github.com/user-attachments/assets/fb3457fb-1296-4f27-8e72-2be2caf2b6eb" />

____


<img width="1039" height="256" alt="Screenshot 2026-08-29 at 1 39 51 PM" src="https://github.com/user-attachments/assets/1e804bf6-6b7f-4285-8d09-310e2cb34525" />

___

## PANEL 4: Failed Logins Within Five Minutes: Potential Brute Forcing


This SPL query detects potential brute-force login activity by analyzing failed Windows authentication events (Event ID 4625) within the windows_lab index. It cleans and identifies the account associated with each failed login by checking multiple username fields, then removes invalid and anonymous account values. The query groups failed authentication attempts into 5-minute time intervals and counts them by account, host, and source network address. Any combination with five or more failed login attempts within a 5-minute period is flagged, and the results are sorted from the highest number of failures to the lowest. This helps highlight suspicious repeated login attempts that may indicate brute-force or password-guessing activity.


______

<img width="661" height="249" alt="Screenshot 2026-08-29 at 1 48 43 PM" src="https://github.com/user-attachments/assets/2192c57b-61cd-4000-a4c1-88f77c3f485f" />

______

<img width="1071" height="262" alt="Screenshot 2026-08-29 at 1 48 31 PM" src="https://github.com/user-attachments/assets/749420a2-f592-4175-ba31-26b4d5a38f1d" />

_____


## PANEL 5: SUCCESSFUL VS  FAILED LOGONS - PAST 30 DAYS


This SPL query compares successful and failed Windows logon activity within the windows_lab index using Event IDs 4624 and 4625. It cleans and normalizes account information across multiple possible username fields while excluding Guest, Anonymous Logon, DWM, and UMFD system-generated accounts. For successful authentication events, the query focuses specifically on Logon Type 2, which represents interactive local logins, while retaining all failed logon events for comparison. It then categorizes each event as either a success or failure, removes duplicate events occurring for the same host, account, event type, logon type, and second, and displays the results in a daily timechart. This visualization helps compare successful versus failed authentication activity over time and can reveal unusual spikes or changes in login behavior.


____

index=windows_lab sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)

| eval Account_Name=mvfilter(
    Account_Name!="-" 
    AND Account_Name!="" 
    AND lower(Account_Name)!="guest"
    AND Account_Name!="ANONYMOUS LOGON"
)

| eval logon_account=coalesce(
    TargetUserName,
    Target_Account_Name,
    user,
    src_user,
    mvindex(Account_Name,0)
)

| eval logon_account=trim(logon_account)

| eval all_account_values=mvappend(
    Account_Name,
    TargetUserName,
    Target_Account_Name,
    user,
    src_user
)

| eval all_account_values_joined=upper(mvjoin(all_account_values,"|"))

| where NOT match(
    all_account_values_joined,
    "(^|\\|)(DWM-[0-9]+|UMFD-[0-9]+)(\\||$)"
)

| where isnotnull(logon_account)
    AND logon_account!=""
    AND logon_account!="-"
    AND lower(logon_account)!="guest"
    AND logon_account!="ANONYMOUS LOGON"

| eval logon_type=tostring(Logon_Type)

| where EventCode=4625
    OR (EventCode=4624 AND logon_type="2")

| eval login_status=case(
    EventCode=4624,"Success",
    EventCode=4625,"Failure"
)

| eval event_second=strftime(_time,"%Y-%m-%d %H:%M:%S")

| dedup host logon_account EventCode logon_type event_second

| timechart span=1d count by login_status

____


<img width="1028" height="262" alt="Screenshot 2026-08-29 at 2 01 11 PM" src="https://github.com/user-attachments/assets/d9f470cb-3f3d-48aa-a048-6dffd2d6e69b" />

____












