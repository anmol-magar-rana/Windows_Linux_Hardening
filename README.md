## Windows_Linux_Hardening
This is a hands on cybersecurity project demonstrating basic secure configuration, endpoint hardening practices, and automation skills.
Please test thoroughly in non-production environments before using any of these scripts. 

This project aims to implement a secure configuration baseline for:

1. Windows 10/11
2. Ubuntu Server (Ubuntu 20+/22+)

## Some skills I developed through this project include:
-   Implementing and maintaining secure technical controls
-   System hardening against common attack vectors
-   Endpoint protection fundamentals
-   Automating security baselines using scripts by using PowerShell & Bash

## Files in this repository:
1. Checklist.md
-   this is a list of policies/recommendations I gathered from online sources to try and implement

2. linux_harden.sh
-   run using "sudo bash linux/hardening.sh" as root
-   this script aims to harden linux systems, specifically Ubuntu, with some policies/recommendations. General overview of implementations:
-   system updates
-   UFW firewall baselines
-   disabling unnecessary services
-   password policies
-   SSH hardening
-   remove insecure SMB/Samba
-   enable auditd
-   kernel hardening
-   file permission tightening
-   cron hardening
-   disable core dumps
-   fail2ban
-   log rotation

3. windows_harden.ps1
-   run using "powershell.exe -ExecutionPolicy Bypass -File .\windows\hardening.ps1"
-   this powershell script aims to harden windows systems with some policies/recommendations. General overview of implementations:
-   disable SMBv1
-   disable unnecessary & high-risk services
-   enforce password & lockout policies
-   enable Windows Firewall for all profiles
-   configure audit policies
-   enable PowerShell script block logging
-   remove consumer bloatware apps
-   disable automatic login

## MITRE ATT&CK Mapping
This project helps to harden against some MITRE ATT%CKs. The following shows the attacks mitigated against and how its done side by side followed by a link for more information about the attack itself:

1. T1021.002: SMB/Windows Admin Share
-  Disable SMBv1, firewall
-  https://attack.mitre.org/techniques/T1021/002/

2. T1003 – Credential Dumping
-  File permissions, audit, patching
-  https://attack.mitre.org/techniques/T1003/

3. T1078 – Valid Accounts
-  SSH hardening, password policy
-  https://attack.mitre.org/techniques/T1078/

4. T1047 – Windows Management Instrumentation (PS)
-  PowerShell logging
-  https://attack.mitre.org/techniques/T1047/

5. T1562 – Impair Defences
-  Auditd, logging, secure configs
-  https://attack.mitre.org/techniques/T1562/

6. T1059 – Command & Scripting Interpreter
-  Logging, restricted permissions
-  https://attack.mitre.org/techniques/T1059/
