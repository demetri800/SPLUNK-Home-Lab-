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
