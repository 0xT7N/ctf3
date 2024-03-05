# SpottedInTheWild challenge

# Q1 In your investigation into the FinTrust Bank breach, you found an application that was the entry point for the attack. Which application was used to download the malicious file?
<br> after investigation in files we found a file called sans sec401 after geting a hash  **74900DD2A29CD5EEBCC259F0265C8425** and check it on virus total we get it is a malicious file 
<br> i uploaded the file also in any.run sandbox to get more details about a file 
<br> so the application was used to download the malicious file is **telegram**
C\Users\Administrator\Downloads\Telegram Desktop\SANS SEC401
![5](https://github.com/0xT7N/ctf3/assets/75274517/99d3b6a6-adef-4c91-b5c4-81a9b834d263)


# Q2 Finding out when the attack started is critical. What is the UTC timestamp for when the suspicious file was first downloaded?
<br> in this Question we can use **MFT** file (MFT file have all information about os which download and more info )
<br> to get info form MFT file we will use two tools first one to convert the file to csv file and the second to display the file 
<br> 1 - MFTcmd  2- timeline explorer
<br> the time is 2024-02-03 07:33:20
![2](https://github.com/0xT7N/ctf3/assets/75274517/cb8d0391-be98-4695-9be8-356edb5bf0cd)
# Q3 Knowing which vulnerability was exploited is key to improving security. What is the CVE identifier of the vulnerability used in this attack?
<br> in this question threat intelligence helped us to detect a cve using two website **1- virustotal   2-any.run**
<br> **CVE-2023-38831**  WinRAR before 6.23 allows attackers to execute arbitrary code .   
<br> to fix this vuln **we have to update  winrar to latest version** above 6.23
![4](https://github.com/0xT7N/ctf3/assets/75274517/559b0510-f568-4225-a377-b81cad7c55ac)
![3](https://github.com/0xT7N/ctf3/assets/75274517/0ae78a4a-92e7-4007-bd6b-c6493a11d84e)

# Q4 In examining the downloaded archive, you noticed a file in with an odd extension indicating it might be malicious. What is the name of this file?
<br> the file with odd ext is **SANS SEC401.pdf .cmd** inside **SANS SEC401.rar** 
![1](https://github.com/0xT7N/ctf3/assets/75274517/8ac5c767-cf50-456d-a162-2c8eae9befbc)

# Q5 Uncovering the methods of payload delivery helps in understanding the attack vectors used. What is the URL used by the attacker to download the second stage of the malware?
<br> in this question we can get it using three method 
<br> **first** if we try to open the file with extention cmd in isolated OS we will the url for the second stage of the malware
![6](https://github.com/0xT7N/ctf3/assets/75274517/df563689-26dc-4d05-ab70-c96f644cc8d2)
<br> **second** we can use  threat intelligence to see the command wrote in cmd with the malicious file using **any.run**
![7](https://github.com/0xT7N/ctf3/assets/75274517/284eeb12-fccc-4ce6-96d7-b84489634a7c)
<br> **third** we can use two to and two tools will give us information **wireshark - FakeNet** we will see the requstes from the milicious website and gain it 
# Q6 To further understand how attackers cover their tracks, identify the script they used to tamper with the event logs. What is the script name?
<br> to see the event logs stored in the sys **C\Windows\System32\winevt\logs**
<br> to see the events we will use application Eventlog explorer 
<br> then now we need to open windows poweshell to see what is inside it 
**Eventlogs.ps1**
![8](https://github.com/0xT7N/ctf3/assets/75274517/31de84ba-26ca-4d9a-bf23-fcbe5b49a8aa)

# Q7 Knowing when unauthorized actions happened helps in understanding the attack. What is the UTC timestamp for when the script that tampered with event logs was run?
<br> we will see the time here but we need -2 to get utc time 
<br> **2024-02-03 07:38:01**
![8](https://github.com/0xT7N/ctf3/assets/75274517/31de84ba-26ca-4d9a-bf23-fcbe5b49a8aa)

# Q8 We need to identify if the attacker maintained access to the machine. What is the command used by the attacker for persistence?
<br> there are more than one persistence technique and all of them will stored in req
<br> the most common will be in ( autorun - task scheduler - ....) and more 
<br> so lets search about it .
<br> then i found it HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\whoisthebaba 
<br> that mean the attacker use Schedule tec to get persistence on the sys
<br> if we look at the command wrote in the cmd using any.run threat intelligence sandobx
<br> we will found it **schtasks /create /sc minute /mo 3 /tn "whoisthebaba" /tr C:\Windows\Temp\run.bat /RL HIGHEST**
![9](https://github.com/0xT7N/ctf3/assets/75274517/573b1c5f-f9bc-428b-8d14-f2ab06b425a2)
![10](https://github.com/0xT7N/ctf3/assets/75274517/bd3fbf44-ab87-4e55-b695-57923fd79ffe)







