## Automated Threat Hunting & Incident Response Lab


**Project Objective:** 

The primary objective of this project is to design and develop an automated threat hunting and incident response environment that strengthens practical skills in cybersecurity investigations, PowerShell scripting, Kali Linux, and security monitoring. This project will focus on advancing beyond basic threat detection by developing custom PowerShell security tools, conducting controlled adversary simulations using Kali Linux, analyzing suspicious activities, and automating investigative workflows through Splunk.

It will incorporate real-world Security Operations Center (SOC) methodologies, including threat hunting, log analysis, event correlation, evidence collection, incident triage, and response procedures. These activities will help develop the technical and analytical skills necessary to identify potential security threats, investigate malicious behavior, and determine appropriate remediation actions.

The final objective is to conduct a comprehensive simulated security incident investigation, document the findings using an incident case-management workflow, and produce a professional incident report containing a detailed timeline, technical evidence, MITRE ATT&CK mappings, impact assessment, and remediation recommendations.

________

## STAGE #1: LEARNING OBJECTIVE** 

**Stage Summary:** 

The primary objective of Stage 1 is to develop a foundational understanding of PowerShell scripting and its practical applications in cybersecurity investigations and Windows system administration. This stage will focus on learning PowerShell syntax, commands, variables, pipelines, conditional statements, loops, functions, and error handling. These concepts will be applied to retrieving and analyzing Windows system information, including running processes, network connections, and security event logs. Through hands-on exercises, the goal is to progressively develop the ability to independently write, troubleshoot, and execute PowerShell scripts that automate repetitive security investigation tasks. By the conclusion of this stage, a functional PowerShell investigation script will be developed to collect, filter, and export relevant Windows security information, establishing the foundation for more advanced threat hunting and automated incident response capabilities in subsequent stages.

____


**LESSON 1.1 - POWERSHELL COMMANDS AND PIPELINES**

_____


**Screenshot 1 — Process Enumeration (Get-Process)**

Executed the Get-Process cmdlet to retrieve information about active processes on the Windows 11 endpoint. This command provides visibility into running applications, process IDs, and resource consumption, establishing a foundation for endpoint investigations.

<img width="675" height="298" alt="Screenshot 2026-10-26 at 12 37 31 PM" src="https://github.com/user-attachments/assets/159eeb8f-eb2a-4181-910d-3198fd7cf004" />

____


**Screenshot 2 — PowerShell Pipeline (Select-Object)**

Utilized the PowerShell pipeline operator (|) to pass process information from Get-Process to Select-Object. Limited the output to the first five processes to demonstrate how pipelines can organize and control command results.

<img width="702" height="209" alt="Screenshot 2026-10-26 at 12 39 09 PM" src="https://github.com/user-attachments/assets/a3042320-83be-4273-a261-21e002f0f569" />

____

**Screenshot 3 — Process Property Selection**

Executed Get-Process with Select-Object to display specific process properties, including ProcessName, Id, and CPU. This demonstrated how to extract relevant information from PowerShell objects for targeted system analysis.

<img width="756" height="327" alt="Screenshot 2026-10-26 at 1 38 51 PM" src="https://github.com/user-attachments/assets/0b951ce5-26c4-4bf5-a86e-f8f27e18da98" />

____

**Screenshot 4 — Process Sorting and Analysis**

Combined Get-Process, Sort-Object, and Select-Object to identify the ten processes with the highest accumulated CPU time. This exercise demonstrated the ability to sort and analyze process information using multiple PowerShell commands.

<img width="1093" height="332" alt="Screenshot 2026-10-26 at 1 20 36 PM" src="https://github.com/user-attachments/assets/088f9ae6-1833-447a-818b-b136135da7c2" />


____


**LESSON 1.2 — VARIABLES, OBJECTS, and FILTERING**

**Objective:**

Develop a foundational understanding of how PowerShell stores, organizes, and filters information using variables and objects. Apply these concepts to retrieve Windows process data, examine individual properties, and isolate process activity based on defined investigative conditions. The goal is to being able to construct PowerShell commands that combine these techniques to retrieve specific security-related information.

___

**Step 1 — Understanding PowerShell variables**

A variable allows you to store information in memory and reference it later without repeatedly executing the original command.

**Screenshot #1 — Variable Assignment**

Created a PowerShell variable to store active Windows process information using the Get-Process cmdlet. Retrieved the number of stored process objects using the .Count property, demonstrating how variables can retain information for further analysis.
___

<img width="928" height="473" alt="Screenshot 2026-10-26 at 1 57 20 PM" src="https://github.com/user-attachments/assets/877b4d13-94f3-4c90-88a5-e02b775435fe" />

<img width="455" height="64" alt="Screenshot 2026-10-26 at 2 06 03 PM" src="https://github.com/user-attachments/assets/464c41b8-d2d2-4424-9f12-098fd3038c3e" />


____


**Step 2 — Understanding PowerShell objects**

When you execute Get-Process, PowerShell returns structured objects. Each process object contains individual properties that describe it.


**GitHub Screenshot #2 — PowerShell Object Properties**

Accessed individual properties of a Windows process object using PowerShell array indexing and the Select-Object cmdlet. Extracted the process name, process ID, and accumulated CPU time to demonstrate targeted retrieval of structured endpoint information.
___

<img width="849" height="369" alt="Screenshot 2026-10-26 at 2 15 40 PM" src="https://github.com/user-attachments/assets/5d0199cb-b978-4495-9076-44f5f6bd53d8" />


**Step 3 — Filtering processes using Where-Object**

Where-Object allows you to return only the objects that satisfy a particular condition. This is especially useful during security investigations when you're dealing with hundreds or thousands of records.

____

**GitHub Screenshot #3 — Process Filtering**

Utilized the Where-Object cmdlet and the -gt comparison operator to filter Windows processes based on accumulated CPU time. This exercise demonstrated how conditional filtering can isolate relevant process information during endpoint investigations.

____

Command Breakdown:

$_ — Current object

Represents the current process being examined as PowerShell evaluates each object in the pipeline.

.CPU — Object property

Specifies which property you're examining.

-gt — Greater than

Compares the CPU property's value against the number 100.

____

<img width="817" height="253" alt="Screenshot 2026-10-26 at 2 21 25 PM" src="https://github.com/user-attachments/assets/be33a212-a126-4d6b-af58-38883df9f591" />


