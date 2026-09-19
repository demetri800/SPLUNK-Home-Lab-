## SPLUNK PURPLE TEAM ATTACK SIMULATION HOME LAB



Project objective Questions: 

What does a suspicious PowerShell attack look like in Sysmon?
What Windows events appear after a failed-login attack?
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

Problems: Atomics reporsitory was present but I was unable to find the attack technique definition in the Atomics Folder, required reinstallation of the Atomics Techniques Folder 


<img width="810" height="114" alt="Screenshot 2026-09-15 at 8 44 08 PM" src="https://github.com/user-attachments/assets/d2fd1171-cced-4cbc-baf1-cb39927a5a5d" />
____


<img width="1115" height="372" alt="Screenshot 2026-09-15 at 8 41 04 PM" src="https://github.com/user-attachments/assets/d5778d51-0694-40b6-9af8-832f6f3f999d" />

____

File was removed again and quarantined by the Windows Security Defender. This prevented me from maintaining the T1059.001 MITRE ATTACK file in the Atomics Folder which I needed to conduct the test. I restored the threat from Windows Security to prevent continuous blocking.

<img width="804" height="640" alt="Screenshot 2026-09-18 at 12 13 27 PM" src="https://github.com/user-attachments/assets/a68b91ca-a28d-4934-bc84-efbaca3003f4" />

____

BAsed on the output the T1059.001.yaml already exists, but Microsoft Defender is blocking PowerShell from reading it. So I had to apply a temporary exclusion for this technique folder. 

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



Investigating powershell activity from splunk otel collector ingestion and identified the process chain from the executed:


Parent Process: powershell.exe {520a07f6-6b70-6aa5-b100-000000000d00}

|

Process GUID: cmd.exe /c powershell.exe -e {520a07f6-70af-6aad-fa0a-000000000d00} 

|

Process GUID: conhost.exe: {520a07f6-70b0-6aad-fb0a-000000000d00} - console window host created by cmd.exe, provides the console interface for command line programs (cmd). 

|

Process GUID: powershell.exe {520a07f6-70b0-6aad-fc0a-000000000d00} - encoded powershell command - suspicious branch of the process tree







