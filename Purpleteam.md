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

## STAGE 2: SYSMON INSTALLATION AND CONFIGURATION<img width="748" height="253" alt="Screenshot 2026-09-05 at 4 25 46 PM" src="https://github.com/user-attachments/assets/fed7aa21-77c5-4901-9513-a20878c275cf" />
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

