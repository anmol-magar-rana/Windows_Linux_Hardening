## This checklist aims to provide some very basic policies or settings recommendations to ensure that both the Windows and Linux systems are secure and hardened against attacks. These will be separated into groups. 

## For a more comprehensive version, information can be found on: https://downloads.cisecurity.org

## 1. Account & password policies
-   Enforce password history to be of 24 passwords.
-   Enforce password length ≥ 14
-   Ensure 'Password must meet complexity requirements' is set to 'Enabled'
-   Enforce lockout after failed attempts
-   Disable guest accounts

## 2. Network Hardening
-   Disable SMBv1
    Server Message Block version 1.0. It is a deprecated, highly vulnerable network protocol.
-   Enable firewall (UFW / Windows Firewall)
-   Restrict inbound ports to required services only (aka Default Deny)
-   Disable unused network services (Telnet, FTP, RDP if not needed)
-   Enforce SSH key auth for Linux

3. System Services
-   Disable autologin
-   Stop and disable:
        1) Print Spooler
        hardens systems against remote code execution and privilege escalation vulnerabilities (PrintNightmare)

        2) Remote Registry
        limiting the ability of remote users to view / modify / delete critical system configurations

        3) Bluetooth (servers)
        eliminate the device’s visibility to hackers, preventing unauthorized pairing + vulnerabilities like "BlueBorne" 
        that allow attackers to steal data, eavesdrop, or gain remote access

        4) Avahi/Bonjour on Linux
        reduces attack surface (closes UDP port 5353) and limiting network information leakage through beaconing

        5) RPC if not needed
        reduces attack surface (closing ports) used in brute-force, DDoS, and remote code execution exploits

4. Logging & Monitoring
-   Enable Windows Event Logs
-   Enable audit policies (logon, process creation, object access)
-   Configure Sysmon (advanced logging details)
-   Enable Linux auditd
-   Enable auth logs and syslogs
-   Configure log rotation

5. File System & Permissions
-   Remove “Everyone” write permissions
-   Lock down /etc, /var/log, and sensitive directories
-   Enable BitLocker / Linux FDE
-   Disable execution on temp directories (noexec for /tmp)

6. Updates & Patch Management
-   Enable automatic Windows Update
-   Enable unattended-upgrades (Linux)
-   Verify package signing
-   Remove outdated packages

7. Misc Hardening
-   Disable macros in Office    - prevents automatic execution of embedded Visual Basic for Applications (VBA) code
-   Remove bloatware
