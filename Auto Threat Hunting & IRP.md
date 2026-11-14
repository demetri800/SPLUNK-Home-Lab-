## Automated Threat Hunting & Incident Response Lab


**Project Objective:** 

The primary objective of this project is to design and develop an automated threat hunting and incident response environment that strengthens practical skills in cybersecurity investigations, PowerShell scripting, Kali Linux, and security monitoring. This project will focus on advancing beyond basic threat detection by developing custom PowerShell security tools, conducting controlled adversary simulations using Kali Linux, analyzing suspicious activities, and automating investigative workflows through Splunk.

It will incorporate real-world Security Operations Center (SOC) methodologies, including threat hunting, log analysis, event correlation, evidence collection, incident triage, and response procedures. These activities will help develop the technical and analytical skills necessary to identify potential security threats, investigate malicious behavior, and determine appropriate remediation actions.

The final objective is to conduct a comprehensive simulated security incident investigation, document the findings using an incident case-management workflow, and produce a professional incident report containing a detailed timeline, technical evidence, MITRE ATT&CK mappings, impact assessment, and remediation recommendations.

________

## STAGE #1: LEARNING OBJECTIVE

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

**Step 1.2.1 — Understanding PowerShell variables**

A variable allows you to store information in memory and reference it later without repeatedly executing the original command.

**Screenshot #1 — Variable Assignment**

Created a PowerShell variable to store active Windows process information using the Get-Process cmdlet. Retrieved the number of stored process objects using the .Count property, demonstrating how variables can retain information for further analysis.
___

<img width="928" height="473" alt="Screenshot 2026-10-26 at 1 57 20 PM" src="https://github.com/user-attachments/assets/877b4d13-94f3-4c90-88a5-e02b775435fe" />

<img width="455" height="64" alt="Screenshot 2026-10-26 at 2 06 03 PM" src="https://github.com/user-attachments/assets/464c41b8-d2d2-4424-9f12-098fd3038c3e" />


____


**Step 1.2.2 — Understanding PowerShell objects**

When you execute Get-Process, PowerShell returns structured objects. Each process object contains individual properties that describe it.


**GitHub Screenshot #2 — PowerShell Object Properties**

Accessed individual properties of a Windows process object using PowerShell array indexing and the Select-Object cmdlet. Extracted the process name, process ID, and accumulated CPU time to demonstrate targeted retrieval of structured endpoint information.
___

<img width="849" height="369" alt="Screenshot 2026-10-26 at 2 15 40 PM" src="https://github.com/user-attachments/assets/5d0199cb-b978-4495-9076-44f5f6bd53d8" />


**Step 1.2.3 — Filtering processes using Where-Object**

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

_____

**Challenge #2 — Investigating a Specific Windows Process**

Scenario: As a SOC analyst, you're reviewing a Windows endpoint and want to identify all instances of svchost.exe running on the system.

_____


<img width="1200" height="197" alt="Screenshot 2026-11-07 at 11 38 33 AM" src="https://github.com/user-attachments/assets/1f3e4b55-27c5-4406-a8be-6fd23e75e10b" />

______

Developed a PowerShell command to identify active svchost process instances using the Where-Object cmdlet and the -eq comparison operator. Extracted relevant process properties to demonstrate the ability to independently filter and investigate specific Windows system processes.

____

**LESSON 1.3 — CONDITIONAL STATEMENTS**

**Objective:**

Develop an understanding of conditional statements and iterative programming in PowerShell, allowing scripts to evaluate security-related conditions and automatically perform different actions based on their findings.

By the end of this lesson, you will be able to:
- Use if, elseif, and else statements to evaluate conditions.
- Understand comparison and logical operators.
- Use foreach loops to process multiple values.
- Combine loops and conditional statements to evaluate Windows processes.
- Create a basic rule-based security analysis script using simulated authentication data.
These concepts form the foundation for automated security investigations.

_____

**Step: 1.3.1**

Monitoring Windows Security Event ID 4625, which represents a failed logon attempt.

You want your script to identify when an account exceeds a specified failed authentication threshold.
_____

**Screenshot #1 — Conditional Threshold Evaluation**
_____

<img width="680" height="132" alt="Screenshot 2026-11-07 at 12 12 35 PM" src="https://github.com/user-attachments/assets/e0c34f9a-7ae3-4cf6-a802-721d02b2a605" />
______

SOC application: This basic logic is one component of threshold-based detections. In an actual investigation, we'd need to count real authentication events within a defined time window and consider factors such as account, source address, and baseline activity.


**Exercise 1.3.2 — Building Multiple Conditions**

Classifying simulated authentication activity into three categories:
- Low activity: fewer than 5 failures.
- Review: 5–9 failures.
- High activity: 10 or more failures.

________

**Screenshot #2 — Multiple Conditional Statements**
_____

<img width="617" height="236" alt="Screenshot 2026-11-07 at 12 32 52 PM" src="https://github.com/user-attachments/assets/1119382c-3ae7-4301-afe6-eb11a314c212" />


**Exercise 1.3.3 — Create a foreach loop**

A loop allows you to execute a block of code repeatedly without manually running the same command each time. Imagine you're reviewing authentication activity involving multiple simulated accounts or events. Rather than analyzing one value at a time, you want the script to process an entire collection.

______

**Screenshot #3 — PowerShell Foreach Loop**
______

<img width="666" height="162" alt="Screenshot 2026-11-07 at 12 48 27 PM" src="https://github.com/user-attachments/assets/a8f03be9-6ead-4f74-be62-9232b7d0847b" />

_____

**Exercise 1.3.4 — Windows Process Inspection**

Writing a script that checks whether specific process names are currently running and reports the results. This is a basic form of automated endpoint inspection.

1. Defines three process names to examine.
2. Iterates through each process name.
3. Uses Get-Process to check for running instances.
4. Stores the returned results in an array.
5. Uses an if statement to determine whether any instances were found.
6. Displays the result for each process.

-ErrorAction SilentlyContinue suppresses non-terminating error messages, including those produced when no process matches a specified name.

Your results will depend on which applications are currently running.

____

**Screenshot #4 — Automated Process Inspection**
_____

<img width="801" height="318" alt="Screenshot 2026-11-07 at 1 17 48 PM" src="https://github.com/user-attachments/assets/bc26256f-f57c-46c5-8a7b-99905a17c995" />

_____


**Challenege #3 — Authentication Activity Classification**

Developed a PowerShell script using foreach iteration and conditional statements to classify simulated failed authentication counts. Implemented threshold-based logic to categorize activity as Low, Review, or High, demonstrating foundational security automation and decision-making capabilities.

_____

<img width="583" height="325" alt="Screenshot 2026-11-07 at 2 10 11 PM" src="https://github.com/user-attachments/assets/69ea8d2b-e6f0-429d-b562-2fb6085465b3" />


**LESSON 1.4 - Understanding PowerShell functions**

**Objective:** 

Develop the ability to create reusable PowerShell functions and implement error-handling mechanisms that allow security investigation scripts to execute reliably, accept input parameters, and respond appropriately to unexpected conditions.

**Exercise 1.4.1 — Create your first function**

_____

**Screenshot #1 — Creating a PowerShell Function**

_____

Developed a reusable PowerShell function to retrieve Windows process information using a configurable input parameter. Demonstrated function creation, parameter passing, and targeted process enumeration to support repeatable endpoint investigations.

_____

<img width="582" height="418" alt="Screenshot 2026-11-11 at 4 54 39 PM" src="https://github.com/user-attachments/assets/960226c7-b618-4d7e-a597-3dd62ef49f64" />


**Exercise 1.4.2 — Create an authentication classification function**

****Screenshot #2 — Parameterized Authentication Analysis****
_____

Developed a parameterized PowerShell function that uses conditional logic to classify simulated authentication failure counts. Integrated the function with a foreach loop, demonstrating reusable decision-making logic for security automation workflows.

_____

<img width="785" height="283" alt="Screenshot 2026-11-11 at 5 31 06 PM" src="https://github.com/user-attachments/assets/1cf5591c-68a3-4e76-a46d-fcfac52370f8" />

______

**Exercise 1.4.3 - Understanding error handling with try and catch**

During an investigation, your script might encounter an unavailable process, inaccessible file, or failed system command.
Without proper error handling, a script might terminate unexpectedly, continue with incomplete information, or produce misleading results.
PowerShell provides try and catch blocks to handle terminating errors
______

**Screenshot #3 — PowerShell Error Handling**

<img width="1097" height="181" alt="Screenshot 2026-11-14 at 12 30 42 PM" src="https://github.com/user-attachments/assets/670c6e34-d173-42ea-9cc8-c0f7c58fa479" />

________

Implemented PowerShell exception handling using try, catch, and -ErrorAction Stop to manage unsuccessful process queries. Demonstrated how security automation scripts can detect execution failures and provide informative warnings rather than silently ignoring errors.

Exercise 1.4.4 — Combining functions and error handling



