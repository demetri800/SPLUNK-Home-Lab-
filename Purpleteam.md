## SPLUNK PURPLE TEAM ATTACK SIMULATION HOME LAB



Project Overview: 

This home lab project was to developed to simulate MITRE ATTACK TECHNIQUES by utilizing the Atomic Red penetration testing tool in a isolated virtual network environment with Kali Linux attacker machine and Windows 11 victim. The techniques included were Encoded Powershell T1059.001, Registry Run Key Persistence T1547.001, Scheduled Task Persistence T1053.005, and SMB Password Guessing T1110. All endpoint based technoques were performed from PowerShell on the Windows 11 virtual machine, with the exception of SMB password guessing activity was generated remontely by Kali. The detection set-up was configured on the Windows 11 VM with SPLUNK Enterprises Open Telemetry Collector and HTTP Event Collector (HEC) to forward Windows Sysmon, Windows Security, and Powershell Script Blocking logs to the reciever to be stored and indexed. With SPLUNKs Search Processing Language (SPL), several detection models with field extraction, timestamping, filtering, and contextual enrichment. The models started from broad searches to verify log ingestion before refining the detection logic to a fully functional alert. Important fields such as process GUID, parent image, user accounts, source IPs, and registry paths, along with additional contextual evidence to correlate events and construct a process chain. Reliability and effectiveness of the detection rules were evaluated through cross source validation with Sysmon, Windows Security, and PowerShell logs. The finalized detections were consolidated into panels on SPLUNKs dashboard for live detection and visualization. This project helps in understanding the role of a purple team SOC analyst, by learning how to investigate incidents from different attack techniques, and analyzing context across a multitude of log sources. 


Objectives:

Build an isolated environment with Kali Linux and Windows and SPLUNK Enterprise SIEM.

Confiure Windows Telemtery using Sysmon, Security, and Powershell Script Block Logging from Windows VM using powershell.

Forward Windows security events into Splunk using the Splunk OpenTelemetry Collector and HTTP Event Collector (HEC).

Simulate adversary techniques mapped to the MITRE ATT&CK framework using Atomic Red Team and controlled Kali Linux activity.

Investigate suspicious behavior by analyzing process execution, parent-child relationships, registry modifications, scheduled tasks, and authentication activity.

Develop SPL Detections:

  - Registry Run Key persistence — T1547.001
  - Scheduled Task creation — T1053.005
  - Repeated failed network logons — T1110
  - Successful authentication following repeated failures — T1110

Correlate multiple Windows events and telemetry sources to reconstruct attack activity instead of relying on individual events alone.

- Validate detections using repeatable attack simulations and evaluate potential false positives.

- Create a Splunk dashboard that provides both high-level security visibility and detailed investigation data.

- Document configuration issues, troubleshooting steps, detection logic, and lessons learned throughout the project.


What parent/child process relationships indicate suspicious execution?
What network activity does an attack generate?
Can I find the activity in Splunk?
Can I turn what I observed into an SPL detection?
Can I rerun the attack and prove the detection works?
How would I reduce false positives without missing the attack?

That is exactly what makes this a purple-team project.

The red-team side generates the behavior.

The blue-team side observes and detects it.

The purple-team part is the feedback loop between the two.

_____

## STAGE 1: FOUNDATION


VM IP ADDRESSES:

Kali: 192.168.64.7/24
Windows 11: 192.168.64.8/24


Networking Tests:

__

<img width="595" height="483" alt="Screenshot 2026-09-05 at 2 48 29 PM" src="https://github.com/user-attachments/assets/938da6ff-3ff4-4114-9fa2-49a369e8b63f" />

___

UTM Cloning Cloning - Backups

<img width="800" height="389" alt="Screenshot 2026-09-05 at 3 30 34 PM" src="https://github.com/user-attachments/assets/de2cf843-e697-4dc0-aa6b-e56358797a67" />

<img width="808" height="392" alt="Screenshot 2026-09-05 at 3 28 40 PM" src="https://github.com/user-attachments/assets/a6546752-2594-46f5-b405-1c738fdc1ad0" />

____

## STAGE 2: SYSMON INSTALLATION AND CONFIGURATION

____

<img width="748" height="253" alt="Screenshot 2026-09-05 at 4 25 46 PM" src="https://github.com/user-attachments/assets/fed7aa21-77c5-4901-9513-a20878c275cf" />



<img width="776" height="238" alt="Screenshot 2026-09-05 at 4 25 27 PM" src="https://github.com/user-attachments/assets/7b13334e-1116-45ed-a046-bebab973f350" />
 

Sysmon itself doesn't decide whether something is malicious. It records evidence. Microsoft specifically describes Sysmon events as observational telemetry rather than alerts; their value comes from correlation and context.Sysmon command provides richer data evidence than windows logs. Deeper visibility and details for windows events.

Process creation

cmd.exe
   ↓
powershell.exe

It can tell you things such as:

Parent process
Process path
Command line
Process ID
Process GUID
User
File hashes
Network connections
DNS queries
Registry activity
File creation
Process access

That means instead of only seeing:

PowerShell ran

you may be able to reconstruct:

WINWORD.EXE
      ↓
powershell.exe
      ↓
encoded command
      ↓
network connection
      ↓
downloaded file
      ↓
new process

Sysmon Startup Configuration: 

<img width="998" height="581" alt="Screenshot 2026-09-05 at 4 05 37 PM" src="https://github.com/user-attachments/assets/8a7d791f-6d0e-408f-be7c-3b37acce0dcb" />


____


<img width="777" height="258" alt="Screenshot 2026-09-05 at 4 25 56 PM" src="https://github.com/user-attachments/assets/46664c0c-ce9b-45ab-a216-d060c3411a5b" />

____

<img width="673" height="427" alt="Screenshot 2026-09-05 at 4 27 06 PM" src="https://github.com/user-attachments/assets/a0546a00-8c9c-4afb-aabb-67f568fa8f70" />

____

This syntax is a little unintuitive.

Because there are no exclusions inside the rule, it effectively means:

Log all process creation events.

Microsoft's current example specifically notes this behavior for empty onmatch="exclude" rules.

We are doing the same thing for:

<NetworkConnect onmatch="exclude" />

and:

<DNSQuery onmatch="exclude" />

So initially we're saying:

Show me everything in these categories so I can learn what normal activity looks like.

Later we'll tune out noise.

____

Testing Process-Create Configurations: 

<img width="606" height="178" alt="Screenshot 2026-09-05 at 4 44 02 PM" src="https://github.com/user-attachments/assets/b3bd5f20-c3fd-4f01-8f63-cbcc75864d3d" />

___

<img width="879" height="386" alt="Screenshot 2026-09-05 at 4 53 02 PM" src="https://github.com/user-attachments/assets/ef5f2b60-bf53-473a-a954-570cdbd3c546" />

____

Sysmon Notepad Process execution test-run: 

<img width="623" height="441" alt="Screenshot 2026-09-05 at 5 09 22 PM" src="https://github.com/user-attachments/assets/a083ba9e-a09c-49dc-85a9-3e8821668746" />

That tells us:

PowerShell launched Notepad.

Later an attack might look like:

WINWORD.EXE
      ↓
powershell.exe
      ↓
rundll32.exe

The same fields allow us to reconstruct that chain.

___

Testing DNS and Network Connection Sysmon Configuraton:

____

<img width="803" height="258" alt="Screenshot 2026-09-05 at 5 18 59 PM" src="https://github.com/user-attachments/assets/1401318e-ce8e-4120-ba0f-494f47c0c82f" />

<img width="627" height="438" alt="Screenshot 2026-09-05 at 5 21 56 PM" src="https://github.com/user-attachments/assets/34033b74-e54d-43c8-b47d-0d6c90945302" />

<img width="626" height="436" alt="Screenshot 2026-09-05 at 5 22 39 PM" src="https://github.com/user-attachments/assets/6d6e5080-bdce-400d-be45-6d2aa5fcaae6" />




ProcessId
    = Windows' current numerical ID for the process

ProcessGuid
    = Sysmon's unique identifier for this particular
      process instance

  ## STAGE 3: SPLUNK INGESTION - SPLUNK OPEN TELEMENTRY COLLECTOR CONFIGURATION

Splunk’s current documentation says the Universal Forwarder can run on Windows 11 ARM under Prism x64 emulation only on a best-effort basis, and specifically says Windows Event Log collection is unsupported/not validated in that configuration. Since Sysmon Event Logs are the foundation of this project, I don’t want us building on an unreliable ingestion method

Splunk Open Telementry Ingester - Supports Windoes 11 - ARM 64


Splunk token creation and HTTP Event Collector



<img width="805" height="582" alt="Screenshot 2026-09-06 at 3 10 09 PM" src="https://github.com/user-attachments/assets/8abd62ed-a860-43a0-b00b-9b773f557f45" />



<img width="662" height="259" alt="Screenshot 2026-09-06 at 3 09 07 PM" src="https://github.com/user-attachments/assets/69d3aea5-34a8-4886-98f8-e52a8626709e" />

Created the Authorization Token for the Collector to verify identity and ingest the sysmon logs.

<img width="760" height="117" alt="Screenshot 2026-09-06 at 3 21 38 PM" src="https://github.com/user-attachments/assets/00495f27-ec9a-49e4-8fba-62f403a2fc24" />


HTTP Splunk Collection Successful:

____

<img width="426" height="176" alt="Screenshot 2026-09-06 at 3 34 22 PM" src="https://github.com/user-attachments/assets/f3e45e2a-8325-456d-bca5-25158c124543" />


<img width="475" height="263" alt="Screenshot 2026-09-06 at 3 33 57 PM" src="https://github.com/user-attachments/assets/617fefa4-40fd-4733-b03a-9022de8e94ef" />


<img width="1170" height="520" alt="Screenshot 2026-09-06 at 3 32 54 PM" src="https://github.com/user-attachments/assets/590128e9-698e-47ce-983b-699640d8e22e" />



Testing Splunk Ingestion from Windows Powershell initiated NetConnection and notepad execution:

_____

<img width="864" height="456" alt="Screenshot 2026-09-06 at 6 18 13 PM" src="https://github.com/user-attachments/assets/a09af5be-43fc-45b8-9edc-5be5f2aa630b" />


Copying audit.yaml open telementry configuration for backup

____

<img width="1164" height="112" alt="Screenshot 2026-09-07 at 4 09 38 PM" src="https://github.com/user-attachments/assets/dabb64b4-7c51-4fd1-9725-d6d9521b5ed4" />

____

Enabling script blocking from Powershell to tell us what powershell actually executed.

___
<img width="1151" height="280" alt="Screenshot 2026-09-07 at 4 13 07 PM" src="https://github.com/user-attachments/assets/b75effe2-6610-4221-923c-d5f1dc4327c9" />


Updated the agent configuration to send windows security logs 

<img width="844" height="510" alt="Screenshot 2026-09-07 at 4 26 10 PM" src="https://github.com/user-attachments/assets/d4808a75-d17d-4c06-9ad0-199fbe4de162" />


Validated configuration of the agent yaml file

<img width="1186" height="201" alt="Screenshot 2026-09-07 at 4 27 26 PM" src="https://github.com/user-attachments/assets/de2d7ad9-37e6-4ed0-83c6-cad3e8b0d13c" />

___

Creating a Powershell Event to Test Ingestion

___


<img width="1192" height="241" alt="Screenshot 2026-09-07 at 5 16 59 PM" src="https://github.com/user-attachments/assets/593f69ae-e3c1-4e07-93f2-7436970638e4" />



Confirming Windows Powershell Events are reaching Splunk Recieving Host

<img width="1269" height="716" alt="Screenshot 2026-09-07 at 5 16 07 PM" src="https://github.com/user-attachments/assets/2c2274cb-cfb5-44d4-b581-698ba17a0834" />

 ## Stage 4: Building the baseline for normal activity: Understanding what legitiamte activity looks like 
 
Understand normal behavior → introduce adversary behavior → identify meaningful differences → build detection logic around those differences. 

___
<img width="1280" height="365" alt="Screenshot 2026-09-12 at 8 59 23 AM" src="https://github.com/user-attachments/assets/065b3e0b-7a10-4922-a4b7-b28e3250e41a" />

Configured the agent YAML file and changed the index purple_team_lab because the windows_lab index was occupied from a past project.

<img width="845" height="513" alt="Screenshot 2026-09-12 at 10 06 26 AM" src="https://github.com/user-attachments/assets/32ea9b70-b835-49cc-a466-7a0bb3d7a3b6" />

___

Edited the HTTP Event Collector and reassigned the index so the token would validate after initial failure

<img width="1096" height="352" alt="Screenshot 2026-09-12 at 10 22 30 AM" src="https://github.com/user-attachments/assets/f3e96e9d-ea80-4bc5-940d-dafd5eee9021" />


<img width="1427" height="276" alt="Screenshot 2026-09-12 at 10 21 12 AM" src="https://github.com/user-attachments/assets/96f6074c-c1ee-4c38-9d74-38c5e9e55657" />

Fixed: 

<img width="1101" height="180" alt="Screenshot 2026-09-12 at 10 23 03 AM" src="https://github.com/user-attachments/assets/4f83d632-ae1a-4ace-87b1-6e1b39c118ed" />


Confirmation from Splunk that it ingested the test event successfully 

<img width="1374" height="617" alt="Screenshot 2026-09-12 at 10 33 56 AM" src="https://github.com/user-attachments/assets/bbdbc892-7dd1-4725-a997-f97a5c62c6b9" />

Creating a normal baseline

<img width="758" height="586" alt="Screenshot 2026-09-12 at 11 24 53 AM" src="https://github.com/user-attachments/assets/a6b1b81c-3a95-4283-865c-35a7c86af0a4" />


Chain Process for Notepad.exe:

<img width="1002" height="228" alt="Screenshot 2026-09-12 at 11 50 17 AM" src="https://github.com/user-attachments/assets/5f291127-693e-4e97-9bbc-78f0c769c72a" />

Chain Process for cmd.exe parent process correlation to whomai.exe 

Powershell.exe -> cmd.exe -> whoami.exe

Process ID cmd.exe = 0x2344 corresponds with the event details found in the whoami.exe process

<img width="913" height="177" alt="Screenshot 2026-09-12 at 12 02 14 PM" src="https://github.com/user-attachments/assets/143e5f5a-b55a-40b9-ae21-60f9a688b69c" />

<img width="692" height="181" alt="Screenshot 2026-09-12 at 12 04 18 PM" src="https://github.com/user-attachments/assets/131c83fb-352c-4bfc-95ab-03662187648d" />


Correlating DNS Query and Test Connection 

____
<img width="720" height="417" alt="Screenshot 2026-09-12 at 12 45 11 PM" src="https://github.com/user-attachments/assets/624f042a-8326-42f2-a0cf-88d57bf244d9" />

____

<img width="923" height="211" alt="Screenshot 2026-09-12 at 12 45 58 PM" src="https://github.com/user-attachments/assets/91341bcf-76bd-4198-aac6-7a0c2a5968c5" />


Beginning phase of establishing baseline events in splunk before replacing _raw with cleaner fields

<img width="1440" height="674" alt="Screenshot 2026-09-15 at 6 25 17 PM" src="https://github.com/user-attachments/assets/1846f038-e218-4a24-aa23-dada30fb15b3" />

_____

Normal Activity Documentation:

Command execution: Notepad.exe - 

Parent Image/Process - powershell.exe

Suspicious: NO 

Manually launched from powershell


Telemetry:
Sysmon Event ID 1
Security Event ID 4688


PowerShell HTTPS Test

Command:
Test-NetConnection 
domain: example.com -Port 443

Suspicious:
No

Telemetry:
PowerShell 4104
Sysmon DNS Event 22
Sysmon Network Event 3

___


Indentifiers for correlating processes:

PID
= useful locally and short-term

ProcessGuid
= stronger correlation identifier

Parent PID / ParentProcessGuid
= immediate parent

Repeated correlation
= full ancestry / process tree


Main goal is converting raw events to: 

PowerShell
   ↓
CMD
   ↓
whoami

Rather than investigating every process event separately.

And this is precisely why we baseline process trees before Atomic Red Team: After I start the attacks, I , should already understand understand how to answer, “what actually initiated this process?” rather than stopping at the immediate parent.



## STAGE 5 - Atomic Red Team Installation and ATTACK SIM 

Objective: 

Select ATT&CK technique
        ↓
Understand the Atomic test
        ↓
Execute it on WIN-VICTIM01
        ↓
Sysmon / Security / PowerShell record it
        ↓
Splunk receives it
        ↓
Compare it against your Stage 4 baseline

Installed Atmomic Red Team and verified installation
<img width="1091" height="454" alt="Screenshot 2026-09-15 at 8 01 59 PM" src="https://github.com/user-attachments/assets/7ca673c9-be09-4f50-be2d-d7e7a247ef84" />

_____

<img width="1022" height="185" alt="Screenshot 2026-09-15 at 8 03 00 PM" src="https://github.com/user-attachments/assets/efe806f7-7490-40db-a821-59afb1a38d9f" />

__

Atomic Red Team organizes test by MITRE ATTACK technique 

Attack technique #1:

T1059.001
Command and Scripting Interpreter: PowerShell

___

Technical Issues & Troubleshooting 

Atomics reporsitory was present but I was unable to find the attack technique definition in the Atomics Folder, required reinstallation of the Atomics Techniques Folder 


<img width="810" height="114" alt="Screenshot 2026-09-15 at 8 44 08 PM" src="https://github.com/user-attachments/assets/d2fd1171-cced-4cbc-baf1-cb39927a5a5d" />
____


<img width="1115" height="372" alt="Screenshot 2026-09-15 at 8 41 04 PM" src="https://github.com/user-attachments/assets/d5778d51-0694-40b6-9af8-832f6f3f999d" />

____

File was removed again and quarantined by the Windows Security Defender. This prevented me from maintaining the T1059.001 MITRE ATTACK file in the Atomics Folder which I needed to conduct the test. I restored the threat from Windows Security to prevent continuous blocking.

<img width="804" height="640" alt="Screenshot 2026-09-18 at 12 13 27 PM" src="https://github.com/user-attachments/assets/a68b91ca-a28d-4934-bc84-efbaca3003f4" />

____

Based on the output the T1059.001.yaml already exists, but Microsoft Defender is blocking PowerShell from reading it. So I had to apply a temporary exclusion for this technique folder. 

<img width="2048" height="431" alt="Screenshot 2026-09-18 at 12 24 54 PM" src="https://github.com/user-attachments/assets/36a68142-7d03-457e-81d5-6caaa863d21a" />

Microsoft documents Add-MpPreference -ExclusionPath as excluding the specified file or folder from Defender's scheduled and real-time scanning. 

Defender quarantined or altered the file before adding the exclusion, requiring me to reinstall the definitions. Upon troubleshoot I successfully accessed the details from the T1059.001 definition. 

___

<img width="1156" height="446" alt="Screenshot 2026-09-18 at 12 40 33 PM" src="https://github.com/user-attachments/assets/caa4567c-22af-463f-a1e7-96b967f19228" />

____

<img width="1113" height="464" alt="Screenshot 2026-09-18 at 12 44 33 PM" src="https://github.com/user-attachments/assets/ad15955c-663b-4ecb-a3a2-975b78d039dd" />

___

Inspected test 17 and verified prerequisites
<img width="1115" height="541" alt="Screenshot 2026-09-18 at 1 07 45 PM" src="https://github.com/user-attachments/assets/cb079294-7f43-45fa-adb4-7a506c937fdf" />

Logged the date and time prior to execution of the attack. 



Investigating powershell activity from splunk otel collector ingestion...

Process Chain:


Parent Process: powershell.exe {520a07f6-6b70-6aa5-b100-000000000d00}

                                           ⬇️

Process GUID: cmd.exe  /c powershell.exe -e  {520a07f6-70af-6aad-fa0a-000000000d00} - this execution launches both conhost and the powershell encoded command 
                     


                     
Parent Image: conhost.exe:                                             
Process GUID: {520a07f6-70b0-6aad-fb0a-000000000d00}:                  
Normal supporting process content console window host created         
by cmd.exe, provides the console interface for command line            
programs (cmd).                      


Parent Image: powershell.exe 
Process GUID: {520a07f6-70b0-6aad-fc0a-000000000d00}
Command line: powershell.exe -e encoded powershell 
suspicious branch of the process tree

 
Analysis chain:


Base 64 Encoded powershell: JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==

Decoded: & (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")

<img width="1170" height="545" alt="Screenshot 2026-09-19 at 11 27 01 AM" src="https://github.com/user-attachments/assets/91a3f05d-19e3-4aca-98cd-d4667c45a0c7" />


<img width="1168" height="587" alt="Screenshot 2026-09-19 at 11 28 20 AM" src="https://github.com/user-attachments/assets/563fdcc8-e20a-4484-8dc3-420f6f6d9561" />


<img width="1132" height="546" alt="Screenshot 2026-09-19 at 11 29 39 AM" src="https://github.com/user-attachments/assets/897ec2f2-65bc-48af-a330-3601c7af216e" />

Conducted Cross source validation to correlate the sysmon with the 4688 windows security event. 


The snapshots below reveal how the powershell parent process launched the cmd.exe prior to the encoded powershell executable from  cmd.exe

SPL Query: index=purple_team_lab "powershell.exe" "4688" "cmd.exe"

<img width="1353" height="605" alt="Screenshot 2026-09-19 at 12 12 20 PM" src="https://github.com/user-attachments/assets/4eb3fefa-eecf-4b38-b466-b6356c61cac7" />

<img width="1367" height="620" alt="Screenshot 2026-09-19 at 12 12 40 PM" src="https://github.com/user-attachments/assets/42571ed2-5772-4b0b-98fc-2a440472706b" />


____


Since this is a simulation, I already know what the decoded scriptblock is. So the SPL search can be, "Hello from Powershell". In real SOC investigations, the search is narrowed by including fields such as host, timestamp, and powershell event type (4104). At this point, I can determine what PowerShell script blocks were recorded immediately after this suspicious PowerShell process started. 

SPL Search: index=purple_team_lab "Microsoft-Windows-Powershell/Operational" "4104" computer="WIN-VICTIM01" earliest="09/18/2026:13:11:15:000" latest="09/18/2026:13:11:18:000"

<img width="979" height="572" alt="Screenshot 2026-09-19 at 1 55 19 PM" src="https://github.com/user-attachments/assets/cbc52016-f05a-40a6-a526-c25da743eed9" />

Snapshot matches the decoded powershell result: & (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")

____

Conclusion: 

For this attack simulation, Atomic Team was used to emulate the T1059 MITRE ATTACK TECHNIQUE, which exploits the Windows powershell native tool by executing commands and scripts. The investigation was conducted by first examining the sysmon events from Splunk ingestion. From there I queried the search for process creation events, occurring around the time-frame of the attack. Based on the results, I discovered an event with details showing command terminal launching an encoded powershell process. To further analyze, I constructed a process chain by correlating those events with their GUIDs and parent-child process relationships.  With this information, I was able to accurately  determine that powershell.exe was the parent process of the cmd.exe, at which point cmd.exe then launched conhost.exe and powershell.exe -e. To identify the content of the encoded script, I copied its text from the event command line details and decoded it with an online base 64 tool, phoenix code. For my next step, I conducted cross source validation against both the sysmon and the 4688 Windows Security Event telemetry to assess detection resilience and confirm reliability. The final step was to examine the powershell encoded process from the splunk events. In my query I included the time, host, and event id 4104. The results revealed a powershell event that contained the scriptblock text, "Hello, from Powershell". The evidence matched the previously decoded result of the powershell. This phase of the project demonstrated how multiple telemetry sources can be correlated to reconstruct suspicious PowerShell execution.


## STAGE 6: DETECTION ENGINEERING

Objective: Building SPL detection rules for encoded powershell processes and its variations. I am also testing the rule by re running Atomic Red to validate its detection capabilities and improving the rule by measure false positives. 

Step #1; Identifying the extracted field names from SPLUNK: 

The event_data field was used to build the detection rules and organize the elements in table format.

event_data
 ├── Image
 ├── CommandLine
 ├── ProcessGuid
 ├── ProcessId
 ├── ParentImage
 ├── ParentCommandLine
 ├── ParentProcessGuid
 ├── ParentProcessId
 └── User

 
<img width="1127" height="249" alt="Screenshot 2026-09-21 at 6 22 40 PM" src="https://github.com/user-attachments/assets/86db899f-b984-4fc4-a982-02bfaea8e429" />


Step #2: Writing an SPL Detection

SPL rule detects a process creation logged by sysmon that matches the commandLine of a powershell encoding and all of its extended variations. However since powershell allows abbreviation usage for parameter names, only searching for powershell -e is not sufficient.

<img width="1417" height="603" alt="Screenshot 2026-09-21 at 6 24 13 PM" src="https://github.com/user-attachments/assets/295b9d94-785d-45f0-aca8-092c77f8dd8a" />


Step #3: Rerunning adversary simulation

Re-running Atomic Red to test newly configured detection rule with timestamp
<img width="1110" height="521" alt="Screenshot 2026-09-21 at 6 36 36 PM" src="https://github.com/user-attachments/assets/08d9c0da-45ee-43bc-91d2-ef7bca3cb33f" />

Step #4: detection automatically identifies the new execution.

The SPL rule successfully detected the encoded powershell process including significant fields.

<img width="1427" height="571" alt="Screenshot 2026-09-21 at 6 35 11 PM" src="https://github.com/user-attachments/assets/576b4fbc-c113-444d-8945-dfdd9bcbcbf0" />

<img width="830" height="321" alt="Screenshot 2026-09-21 at 6 55 46 PM" src="https://github.com/user-attachments/assets/d27aaedd-6d40-4a7c-a0c8-4068dfec1a80" />


Step #5: Generating harmless powershell activity

Testing for detection rule for false positives by initiating a Write-Ouput process. I performed this by generating benign PowerShell activity. The benign activity did not match.

<img width="912" height="220" alt="Screenshot 2026-09-22 at 10 17 08 PM" src="https://github.com/user-attachments/assets/16e3ec05-7b62-40e0-b213-4e7bcf350372" />


<img width="761" height="71" alt="Screenshot 2026-09-22 at 10 17 23 PM" src="https://github.com/user-attachments/assets/210254b9-4b7d-4be0-b3d9-531619000864" />


<img width="1418" height="520" alt="Screenshot 2026-09-22 at 10 18 00 PM" src="https://github.com/user-attachments/assets/6ab2d0b6-7e53-4097-af87-bf44800be41b" />

____


Validating detection configuration by using paramter variations of encoded powershell.

<img width="1120" height="220" alt="Screenshot 2026-09-22 at 10 58 36 PM" src="https://github.com/user-attachments/assets/1ec98860-01d1-4116-b12a-1d1d5b5a4a50" />



<img width="1435" height="695" alt="Screenshot 2026-09-22 at 10 57 34 PM" src="https://github.com/user-attachments/assets/dfbc9b9e-29ef-4f52-987f-2d51d5e160b3" />

____

Sysmon used to detect the suspicious process → Powershell 4104 reveals the powershell script being executed

Conducting cross-checking on Windows Powershell Events 

<img width="905" height="171" alt="Screenshot 2026-09-23 at 7 25 39 PM" src="https://github.com/user-attachments/assets/04c83684-e9c8-499a-80ea-84600571aafe" />


<img width="974" height="115" alt="Screenshot 2026-09-23 at 7 19 11 PM" src="https://github.com/user-attachments/assets/ed132fa7-1ef8-4221-bd37-0acac570006f" />

<img width="739" height="113" alt="Screenshot 2026-09-23 at 7 23 43 PM" src="https://github.com/user-attachments/assets/61f103f3-78d9-464b-9e86-0ee1dc442f77" />

Improving Detection by impplementing Parent Process Context 

My goal is the let the alert show the parent but not only limited to cmd.exe in the previous example because endcoded powershell can be launched by something else.

This add-on allows the me to detect processes initiated by various parent images that could also potentially star-up powershell scripts, other than cmd.exe. 


<img width="1026" height="425" alt="Screenshot 2026-09-23 at 7 43 15 PM" src="https://github.com/user-attachments/assets/5fa953bc-7106-4b6a-aea2-3fa07ab819ed" />


<img width="1415" height="90" alt="Screenshot 2026-09-23 at 7 58 18 PM" src="https://github.com/user-attachments/assets/6a7d4d19-9b49-4711-ae0f-80f3b05f4d83" />



A useful detection explains what it detects, why it matters, how it was tested, and how an analyst should investigate it.

<img width="787" height="208" alt="Screenshot 2026-09-23 at 8 09 24 PM" src="https://github.com/user-attachments/assets/f5f00c6c-f7ac-44c4-ad29-f5bd64ba742c" />

<img width="566" height="68" alt="Screenshot 2026-09-23 at 8 09 47 PM" src="https://github.com/user-attachments/assets/2d51f818-ea4e-419e-86df-f1deb9db8ead" />

Detection Name:
Encoded PowerShell Execution

MITRE ATT&CK:
T1059.001 — PowerShell

Data Source:
Sysmon Event ID 1

Objective:
Identify PowerShell processes launched with encoded-command
arguments.

Detection Logic:
Identify powershell.exe process creation events where the
command line contains variations of -EncodedCommand such as
-e, -enc, or -EncodedCommand.

Primary Fields:
Image
CommandLine
ParentImage
ParentCommandLine
User
ProcessGuid
ParentProcessGuid

Validation:
Atomic Red Team T1059.001 Test #17

Result:
Successfully detected Atomic execution.

Negative Testing:
Normal PowerShell commands such as Get-Date and Get-Process
did not trigger the detection.

** Potential False Positives **
Legitimate administrative automation or management software
that uses encoded PowerShell.

Investigation Guidance:
Review parent process, user, host, decoded command content,
PowerShell 4104 telemetry, and subsequent process/network
activity.

Detection Status:
Validated


## STAGE 7: REGISTRY RUN-KEY PERSISTANCE 

Objective: Simulate a persistence mechanism where an attacker places a command or executable path in a Windows autorun registry location so it can execute when the user logs on. Atomic Red Team currently lists Test #1, “Reg Key Run,” which adds an Atomic Red Team value under the current user's Run key and provides a cleanup command afterward


Step #1: Verfiy Sysmon registry event collection 

Event 12: registry key/value create or delete
Event 13: registry value set
Event 14: registry key/value rename


Appending registry event collection to the sysmon.xml file
<img width="637" height="378" alt="Screenshot 2026-09-26 at 11 33 37 AM" src="https://github.com/user-attachments/assets/53ee81bd-4fe7-46c9-b56b-bd84a978644c" />

Confirming registry event appears in the updated configuration 
<img width="845" height="416" alt="Screenshot 2026-09-26 at 11 35 15 AM" src="https://github.com/user-attachments/assets/1b81cb9d-d6e6-4ed9-849e-fb5ddd7c6a83" />

Testing SPLUNK ingestion by creating a registry event to prove registry Telementry works 

<img width="1113" height="273" alt="Screenshot 2026-09-26 at 11 39 34 AM" src="https://github.com/user-attachments/assets/98930160-771d-4245-a9e6-b62625f6b8cd" />

<img width="1435" height="619" alt="Screenshot 2026-09-26 at 11 50 49 AM" src="https://github.com/user-attachments/assets/b0d3fa93-f910-4d2f-8b8c-a2fa1aec4168" />


Key Fields: These particular fields are necessary for building the process trees for registry specific event 

Image
    What program modified the registry?

TargetObject
    What registry key/value was changed?

Details
    What data was written?

ProcessGuid
    Which exact process performed it?

User
    Which account performed it?




<img width="1430" height="637" alt="Screenshot 2026-09-26 at 12 28 01 PM" src="https://github.com/user-attachments/assets/f9c8beca-fcaf-45e5-86c9-89b0367aa6f0" />

Atomic Red MITRE ATTACK T1547.001 was performed, logged by Sysmon, and ingested into SPLUNK. 

<img width="1413" height="539" alt="Screenshot 2026-09-26 at 12 51 41 PM" src="https://github.com/user-attachments/assets/67939f53-2163-43fe-8e22-4cc90a6ea2fb" />

Process was identified:

reg.exe → modified → HKCU\Software\Microsoft\Windows\CurrentVersion\Run → added "Atomic Red Team" → C:\Path\AtomicRedTeam.exe

Step #8: Correlating Registry back to the process:

Event ID: 1 Sysmon Process creation was recorded with included registry telemetry and process chain details. 
<img width="1176" height="611" alt="Screenshot 2026-09-26 at 1 31 38 PM" src="https://github.com/user-attachments/assets/4413d680-a751-4a89-a160-21b4e9a4fc1e" />


parent process: cmd.exe → reg.exe →  HKCU\Software\Microsoft\Windows\CurrentVersion\Run → C:\Path\AtomicRedTeam.exe

Step #9: Cross-Check validating to the Windows Event 4688 logs

<img width="1142" height="595" alt="Screenshot 2026-09-26 at 1 38 16 PM" src="https://github.com/user-attachments/assets/07815501-2afd-4095-813f-ddcea7a0480f" />

Confirms that the windows event security log also identified and captured the process creation of the registry key modification. 

Step #10: Building real dectection against potentially malicious registry key changes   

<img width="1191" height="344" alt="Screenshot 2026-09-26 at 2 07 48 PM" src="https://github.com/user-attachments/assets/0c6211d1-2c0c-49a5-b402-98a8d17d65c7" />

This detection functions by identifying a high value persistence location being modified. The context provided by the event is used to  understand why a result may deserve further investigation. The goal is for the system to alert based on behavior rather than artifact specific detection. A detection rule that actively seeks for a specific keyword such as "Atomic Red Team" is ineffective, because attackers can label this value anything.  


Detection Logic Walkthrough: 

index=purple_team_lab event_id.id=13 → Examine Sysmon 13 events only

| spath path=event_data.Image output=Image
| spath path=event_data.TargetObject output=TargetObject
| spath path=event_data.Details output=Details.  
| spath path=event_data.ProcessGuid output=ProcessGuid
| spath path=event_data.ProcessId output=ProcessId
| spath path=event_data.User output=User 

→ extract these keys from the parent object event.data . 
→ output: Take that value and save it into a clean new field. 

| where like(TargetObject,"%CurrentVersion%Run%") → Only keep registry changes where the registry path contains CurrentVersion and later contains Run


The keys are folders that contain the configuration settings of how your devices system and applications start-up and operate. The critical keys like autorun logon and defense keys are targeted by attackers to establish persistence upon log-on or disable security

Step #11: Validate

Proves that legitamite software can also run keys and which may create instances of false positives 

<img width="1109" height="98" alt="Screenshot 2026-09-26 at 3 31 11 PM" src="https://github.com/user-attachments/assets/e459304e-e059-4570-9bfe-11903ebf4eaa" />

<img width="1434" height="647" alt="Screenshot 2026-09-26 at 3 30 43 PM" src="https://github.com/user-attachments/assets/1d785338-96af-4605-9ec3-938f95c6e072" />

Sysmon 13 events successfully detects T1547.001 ATTACK technique against the registry 

<img width="1170" height="469" alt="Screenshot 2026-09-26 at 4 06 49 PM" src="https://github.com/user-attachments/assets/19708e96-f1fa-456f-ba2c-847a825c9555" />

<img width="1385" height="408" alt="Screenshot 2026-09-26 at 4 07 17 PM" src="https://github.com/user-attachments/assets/8a6d21e0-c97e-40aa-b4df-f116bbb95da5" />


<img width="869" height="237" alt="Screenshot 2026-09-27 at 12 27 31 PM" src="https://github.com/user-attachments/assets/5198040e-5ca7-49d1-853b-eac31213d2ff" />

Detection:
Registry Run Key Persistence

MITRE ATT&CK:
T1547.001

Data Source:
Sysmon Event ID 13

Detection Logic:
Detects registry value writes involving Windows
CurrentVersion\Run / RunOnce autorun locations.

Important Fields:
Image
TargetObject
Details
User
ProcessGuid

Validation:
Atomic Red Team T1547.001 Test #1

Cross-Source Validation:
Sysmon Event 1 →  Security 4688 →  Sysmon Event 13

Potential False Positives:
Legitimate applications installing or updating
autorun components.

Investigation:
Determine what process made the change, what executable
was configured, where that executable resides, which user
performed the modification, and what preceded the action.




## STAGE 8: Scheduled ATTACK persistence

Objective: Detecting creation of scheduled tasks falling under MITRE ATT&CK T1053.005. We are determining what created the task, what the task executes, the account that triggered it, and its behavior. Upon investigation and acquired context, we develop our SPLUNK detection rules flag processes worth investigating. Lastly, we validate the detection system and its capabilities by cross-checking other log sources to build the evidence-chain. Windows Security Event 4698 is specifically generated when a scheduled task is created, provided the relevant audit policy is enabled. Microsoft also recommends monitoring scheduled-task creation because malware can use tasks for persistence or execution. Task creation in Windows lets you automate programs, scripts, or system commands to run automatically using the built-in Task Scheduler tool.

Step #1: Enables successful Auditing 

The follwoing powershell commands allowing windows security to produce events such as:

4698 = Scheduled task created
4699 = Scheduled task deleted
4700 = Scheduled task enabled
4701 = Scheduled task disabled
4702 = Scheduled task updated

<img width="1069" height="167" alt="Screenshot 2026-09-27 at 12 44 36 PM" src="https://github.com/user-attachments/assets/51f43d02-5049-4c20-826f-ed627ae362af" />

For this stage, I am choosing test #1 - scheduled task startup which creates two tasks OnLogon and OnStartup

<img width="877" height="354" alt="Screenshot 2026-09-27 at 12 53 28 PM" src="https://github.com/user-attachments/assets/5695aa1d-a6e7-444e-b511-e6d8748b9f02" />

Step#4: Finding the Security 4698 Event in SPLUNK

<img width="1440" height="665" alt="Screenshot 2026-09-27 at 2 24 07 PM" src="https://github.com/user-attachments/assets/1c97477c-01f1-41ab-b824-4f02ae1cf3ab" />

<img width="1438" height="677" alt="Screenshot 2026-09-27 at 2 57 02 PM" src="https://github.com/user-attachments/assets/4a08a8bf-28e2-492a-b81d-5ec9cf5ee538" />

Important Fields: 

SubjectUserName
→ Who requested the task creation?

TaskName
→ What task was created?

TaskContent
→ What exactly is the task configured to do?

ClientProcessId
→ Which process requested creation?

ParentProcessId
→ What created that process?



<Triggers> → WHEN will it execute?  <StartBoundary>2026-09-27T14:00:00</StartBoundary>

<Principals> → WHO will it run as? - <user ID> S-1-5-18

 
 <Command>...</Command> → What will execute? cmd.exe
 +
 <Arguments>...</Arguments> c calc.exe


Step #7: Finding the process that created the task

The following image details the sysmon log event.id 1  

<img width="1440" height="676" alt="Screenshot 2026-09-27 at 5 59 24 PM" src="https://github.com/user-attachments/assets/cb7bf832-70e1-4995-9f46-84d0731674d6" />


<img width="1077" height="475" alt="Screenshot 2026-09-27 at 6 53 30 PM" src="https://github.com/user-attachments/assets/abda20d7-fec9-47cb-8709-d534575a39fe" />


Name of the scheduled task: T1053_005_OnStartup

cmd.exe /c calc.exe → scheduled task launches cmd.exe, and cmd.exe is told with /c to run calc.exe and then exit.


Step #8


Confirmation cross source validation was successful with Sysmon even 1, Windows 4688 and 4968 logsources detected the task creation. 

Sysmon 1

<img width="1151" height="616" alt="Screenshot 2026-09-28 at 11 14 28 AM" src="https://github.com/user-attachments/assets/3c47a165-634b-485a-aa7e-835b27e42dc4" />


<img width="1159" height="607" alt="Screenshot 2026-09-28 at 11 15 44 AM" src="https://github.com/user-attachments/assets/c2b4f985-0340-409f-ad5b-1ebd917d51ba" />


Windows Security 4688

<img width="1018" height="575" alt="Screenshot 2026-09-28 at 11 11 21 AM" src="https://github.com/user-attachments/assets/0b71cca0-3861-4ad8-be2b-b3e219bdc9a0" />

<img width="1040" height="562" alt="Screenshot 2026-09-28 at 11 16 49 AM" src="https://github.com/user-attachments/assets/f3260345-8ed2-404b-bf65-eb3d543d0cc2" />

Windows Security 4698 


<img width="1440" height="582" alt="Screenshot 2026-09-28 at 11 40 59 AM" src="https://github.com/user-attachments/assets/07bf03fd-5a95-45fe-86e2-7b6212fc957f" />

<img width="1440" height="591" alt="Screenshot 2026-09-28 at 11 41 15 AM" src="https://github.com/user-attachments/assets/b697b8eb-6faa-4c7f-84ce-1075b0751c8c" />

Sysmon 1
schtasks.exe process creation
        ↓
Security 4688
independent process creation record
        ↓
Security 4698
scheduled task actually created
        ↓
TaskContent XML
reveals trigger + command + principal


Step #9: Building Scheduled detection

This is a broader search that detects all task creation events and organizes events in table format

index=purple_team_lab event_id.id=4698
| spath path=event_data.TaskName output=TaskName
| spath path=event_data.TaskContent output=TaskContent
| spath path=event_data.SubjectUserName output=SubjectUserName
| spath path=event_data.SubjectDomainName output=SubjectDomainName
| spath path=event_data.ClientProcessId output=ClientProcessId
| spath path=event_data.ParentProcessId output=ParentProcessId
| eval detection_name="Scheduled Task Creation"
| eval mitre_technique="T1053.005"
| table _time host SubjectDomainName SubjectUserName detection_name mitre_technique TaskName TaskContent ClientProcessId ParentProcessId


This part is as an extension of the previous query allowing the detection rule to match the task content with keywords such as powershell, cmd, and rundll32. These are among the more common exploitable services that threats typically use when performing task creation attacks to maintain persistence on a victims machine:

| eval context=case(
    match(TaskContent,"(?i)powershell(\.exe)?"),"PowerShell execution",
    match(TaskContent,"(?i)cmd(\.exe)?"),"Command shell execution",
    match(TaskContent,"(?i)mshta(\.exe)?"),"MSHTA execution",
    match(TaskContent,"(?i)rundll32(\.exe)?"),"Rundll32 execution",
    match(TaskContent,"(?i)wscript(\.exe)?|cscript(\.exe)?"),"Windows Script Host execution",
    match(TaskContent,"(?i)\\Temp\\|\\AppData\\|\\Downloads\\"),"User-writable path",
    true(),"Review task creation"
)
| table _time host SubjectDomainName SubjectUserName detection_name mitre_technique context TaskName TaskContent ClientProcessId


SPL Command explained:

| eval taskcontent_lower=lower(TaskContent) → converts all of "TaskContent" into to lowercase.

like(taskcontent_lower,"%cmd.exe%") → Asks the question, does the task content contain cmd.exe anywhere?
The % characters mean "anything can appear before or after this."

Splunk sees: cmd.exe /c calc.exe 

like(taskcontent_lower,"%cmd.exe%") → CONDITION = TRUE 

THEN:

Splunk assigns → context = Command shell execution



Step #10: Peforming Negative Testing


Creating a harmless scheduled task to prove detection rule functionality

<img width="1119" height="227" alt="Screenshot 2026-09-28 at 12 13 18 PM" src="https://github.com/user-attachments/assets/dd1ed2eb-285c-40d5-b244-358a7d520286" />


Context fields works as intended and assigns "review task creation" instead of "Command shell execution" or "Powershell Execution". This demonstrates how this detection system can highlight alerts based on contextual classification.

<img width="1440" height="567" alt="Screenshot 2026-09-28 at 12 13 06 PM" src="https://github.com/user-attachments/assets/35faccc0-cf66-40e9-b589-fd71dd108311" />


Validated Atomic and the production of new test events:

<img width="959" height="177" alt="Screenshot 2026-09-28 at 12 54 01 PM" src="https://github.com/user-attachments/assets/8113989b-eae4-4ce1-b644-a93d0b5b78de" />


Invoke-AtomicTest T1053.005 -TestNumbers 1

<img width="1117" height="637" alt="Screenshot 2026-09-28 at 12 52 44 PM" src="https://github.com/user-attachments/assets/cc60b46e-e044-4797-895a-c0044b0e21d3" />
 

<img width="968" height="181" alt="Screenshot 2026-09-28 at 12 57 42 PM" src="https://github.com/user-attachments/assets/61633c2e-76c7-436d-bcd9-f4121ac872e2" />

{Edit Detection Summary} 

Detection:
Scheduled Task Creation

MITRE ATT&CK:
T1053.005 — Scheduled Task

Primary Data Source:
Windows Security Event 4698

Supporting Sources:
Sysmon Event ID 1
Windows Security Event 4688

Detection Objective:
Identify newly registered scheduled tasks and expose
their trigger, execution command, account, and creating process.

Validation:
Atomic Red Team T1053.005 Test #1

Observed behavior:
schtasks.exe created logon/startup tasks configured
to execute cmd.exe /c calc.exe.

Potential False Positives:
Software installers, update agents, administrative
automation, maintenance jobs, and enterprise management tools.

Investigation:
Review task name, XML action, arguments, trigger,
principal, creating account, creating process, and surrounding
process/network activity.

Kali Network Attack Simulation 

## STAGE 9: Kali Network Attack Simulation - Brute Forcing

KALI-RED01 → Network reconnaissance → WIN-VICTIM01 → SMB authentication attempts → Windows Security 4625 → 
Splunk → Brute-force-detection

Step #1: Ensuring connectivity between windows and kali machine 

<img width="485" height="116" alt="Screenshot 2026-09-28 at 3 11 41 PM" src="https://github.com/user-attachments/assets/f45e40ce-88a4-4371-b956-a2fcfca2fa2f" />

<img width="726" height="259" alt="Screenshot 2026-09-28 at 3 11 55 PM" src="https://github.com/user-attachments/assets/5e69a9f3-5dee-4639-8e21-443426eecaee" />


____

Nmap was tested from Kali on the WindowsVIC-01 but the the windows firewall blocked the port status details. Unable to determine if any of the ports are open or closed. 

<img width="528" height="233" alt="Screenshot 2026-09-28 at 3 26 55 PM" src="https://github.com/user-attachments/assets/737752cc-b9eb-445f-83c0-51eec184eab1" />


Configuring Windows Firewall Rules to allow inbound TCP 445 connections so the Kali Attack can be simulated

<img width="1104" height="526" alt="Screenshot 2026-09-28 at 4 02 59 PM" src="https://github.com/user-attachments/assets/4912123b-7d3b-4ea2-8f71-8205e424d615" />

After modifying firewall rules the Kali nmap port scan test was successful 

<img width="521" height="164" alt="Screenshot 2026-09-28 at 4 07 57 PM" src="https://github.com/user-attachments/assets/73a944c3-cc03-4a36-ba28-031331b16369" />

Installing smb client on kali and initializing logon sessions

Intentional failure (5x) for brute force detection on Splunk

<img width="537" height="258" alt="Screenshot 2026-09-28 at 4 24 45 PM" src="https://github.com/user-attachments/assets/73980069-2730-4492-9bde-8a50cb415adb" />

Splunk detected all five logon failures originating from the kali machine 

Target UserName= Demetrius 
Kali IP = 192.168.64.7 
Logon Type = 3 

<img width="817" height="611" alt="Screenshot 2026-09-28 at 4 29 11 PM" src="https://github.com/user-attachments/assets/731ebfd3-7a83-4c03-85af-3f390decc54e" />

<img width="1440" height="534" alt="Screenshot 2026-09-28 at 4 34 40 PM" src="https://github.com/user-attachments/assets/6cde52da-a537-4019-a79b-e741dbf93140" />

The status columns provide additional information on why they logon failed

Status - 0xc000006d - Windows logon failure due to a bad username, incorrect password, or invalid authentication information
Sub-status - 0xc000006a - UserName was correct but the password is wrong 

WorkstationName and IP address defines what account/source generated them.

Step #9: Enriching Detection by implemeting a 5 minute window Threshold

The following SPL command was built for tracking logon attempts exceeding or equal to five occurring within a five minute timeframe. 

<img width="1433" height="572" alt="Screenshot 2026-09-28 at 4 54 24 PM" src="https://github.com/user-attachments/assets/5f40f8ad-d932-4db7-b19e-0649c773b9a1" />

| bin _time span=5m - breaks activity into five minute windows 
| stats count as failed_attempts by _time host IpAddress TargetUserName - during this five minute period how may logon attempts came from this IP against this account on this host. 

| where failed_attempts >= 5 - there was at least five logon failure attempts

This SPL detection rule demonstrates how password attempts appears based on set conditions indicative of brute forcing. 


<img width="1434" height="587" alt="Screenshot 2026-10-03 at 9 41 51 AM" src="https://github.com/user-attachments/assets/4e7180e3-0d73-4e73-b777-8271e42a24b0" />

____

This new rule enhance the pervious base detection by defining the severity based on the amounted logon attempts. Due to the SMB  authentication lock out, I was unable to reach the "high volume failed authentication". However I was able to simulate brute forcing with 10 logon attempts to demonstrate the "elevated failed authentication" context variation. 

<img width="611" height="380" alt="Screenshot 2026-10-03 at 10 50 46 AM" src="https://github.com/user-attachments/assets/c79e2a5e-593e-432f-973a-d5cceba27061" />

<img width="1384" height="537" alt="Screenshot 2026-10-03 at 10 04 58 AM" src="https://github.com/user-attachments/assets/7b435781-f33a-4c7c-b999-9219b7c4ce5f" />

<img width="1388" height="161" alt="Screenshot 2026-10-03 at 10 05 18 AM" src="https://github.com/user-attachments/assets/34dee98e-be3f-4a9d-85c7-2ec0c034c3d7" />

Edit ****
Technique:
T1110 — Brute Force

Data Source:
Windows Security Event 4625

Attack Source:
KALI-RED01

Target:
WIN-VICTIM01

Detection:
5 or more authentication failures from the same
source IP against the same account within 5 minutes.

Validation:
Five intentionally failed SMB logon attempts from Kali.

Expected Evidence:
Source IP = Kali
Target account = Demetrius
Logon Type = 3

Edit****


## STAGE 10: SMB CORRELATION


Objective: This stage acts as a follow up to stage 9 by correlating a sequence of authentication events into one suspicious incident. The goal now is to determine if the same source responsible for the failed authentication attempts eventually successful. 


Step #1: Generating correlation sequence by simulating failed logon attempts 

<img width="502" height="198" alt="Screenshot 2026-10-03 at 12 42 15 PM" src="https://github.com/user-attachments/assets/8042fc47-c08f-49c6-ac45-81e6a32d0384" />


Step #2: Confirmation of the failed smb logon events from SPLUNK ingestion


<img width="1412" height="483" alt="Screenshot 2026-10-03 at 12 50 49 PM" src="https://github.com/user-attachments/assets/94289714-d1be-4281-975f-cccd84340314" />


Step #3: Successful Authentication confirmed


<img width="1434" height="388" alt="Screenshot 2026-10-03 at 1 01 18 PM" src="https://github.com/user-attachments/assets/538bf108-470b-4091-83e0-9a8ed04283e3" />

Step #4: Consolidating failures and successful logons to establish a timeline 


<img width="1419" height="652" alt="Screenshot 2026-10-03 at 2 08 24 PM" src="https://github.com/user-attachments/assets/04b38b8c-1e2f-40e7-9b43-d45ec79bd33a" />

Step #5: Correlation detection build 

The detection works differently by  counting the successful logons only after at least 5 failed attempts were conducted prior. This query reveals more context other than it just showing  the number of failed logons. We now have a sequence that reveals an indication of a possible password guessing attack that was successful. This may not always be the case, but atleast provides substantial evidence to investigate further. 

<img width="1412" height="649" alt="Screenshot 2026-10-03 at 2 41 52 PM" src="https://github.com/user-attachments/assets/158aba47-ba98-41d0-a33d-c3339bccb0c9" />

Investigation Steps:

Was the source IP expected for that account logon? 

Does the authentication method makes sense and is it normal according to the the baseline of normal activity?

Do the failures immediately precede the success?

What activity occurred after authentication? 

Detection:
Successful Network Logon After Repeated Failures

MITRE ATT&CK:
T1110 — Brute Force

Primary Events:
Windows Security 4625
Windows Security 4624

Objective:
Identify successful network authentication from a
source IP/account combination following at least five
failed authentication attempts within five minutes.

Attack Source:
KALI-RED01

Target:
WIN-VICTIM01

Validation:
Five intentional SMB authentication failures followed
by one successful SMB authentication.

Correlation Fields:
Source IP
Target account
Destination host
Timestamp
Logon type

## STAGE #11: FINALIZED SOC DASHBOARD 

Objective: This final stage of my project focuses on consolidating all of the SPL detection model results and developing panels for each of them on the SOC dashboard. For this part, I did perform some minor alterations to the original SPL commands which allowed me to represent the data in different ways. I also configured the dashboard to be interactive, allowing the search results to open in a new tab on-click. 


Panel #1: Encoded Powershell 

This panel is derived from the stage 5 process of the simulated command and scripting MITRE TECHNIQUE T1509. 

<img width="1398" height="339" alt="Screenshot 2026-10-06 at 11 32 16 PM" src="https://github.com/user-attachments/assets/6b77d22d-b798-41e6-922f-945fdb03b99b" />

___

Panel #2: Registry Persistence

<img width="1410" height="295" alt="Screenshot 2026-10-06 at 11 32 54 PM" src="https://github.com/user-attachments/assets/7b2603a6-fec4-49ec-bdc0-148a80af9dd9" />

__

Panel #3: Scheduled Task Creation

<img width="1404" height="197" alt="Screenshot 2026-10-06 at 11 33 41 PM" src="https://github.com/user-attachments/assets/dfa32b1f-d9ea-4586-bd97-835b8fa00153" />

__

Panel #4: Repeated Failed Network Logons

<img width="724" height="262" alt="Screenshot 2026-10-06 at 11 35 22 PM" src="https://github.com/user-attachments/assets/8bb70c71-dbe9-4f08-9840-c00c61412e83" />

__

Panel #5: Successful Login Following Repeated Failures

<img width="1413" height="210" alt="Screenshot 2026-10-06 at 11 35 43 PM" src="https://github.com/user-attachments/assets/40bec732-ea8b-4b51-9d25-5bcc6e20e372" />

__

Panel #6: Event Telemetry Overview

<img width="688" height="266" alt="Screenshot 2026-10-06 at 11 36 31 PM" src="https://github.com/user-attachments/assets/8bfb46af-d2dc-4d5d-98fe-5331741c5149" />



