<#
Basic Windows Hardening Baseline Script
Author: Anmol Rana

This script is built by scourcing from publicly available sources from 
Microsoft, CIS recommendations, and community tutorials. 
All consolidation was done by me.
#>

#ensure this script is run as admin, otherwise stop and exit
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Warning "Run PowerShell as Administrator!"
    exit
}

# after ensuring the powershell is run as admin, start the hardening process. first print out message that it is starting
Write-Host "`n===== WINDOWS HARDENING STARTED =====" -ForegroundColor Cyan

# function that disable SMBv1
function disable_SMBv1 {
    Write-Host "Disabling SMBv1..."
    Disable-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol `
        -NoRestart `
        -ErrorAction SilentlyContinue
}
disable_SMBv1



# disable unnecessary services
function disable_unnecessary_services {
    Write-Host "Disabling unnecessary services:"

    #create an array of the services to be disabled
    $services = @(
        "RemoteRegistry",
        "Spooler"     
    )

    #run a loop through all the services and disable them
    foreach ($svc in $services) {
        Write-Host "    - $svc"
        #force stop services
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        #disable startup activation
        Set-Service  $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}
disable_unnecessary_services


# enforce password policies
function set_password_policy {
    Write-Host "Enforcing password/lockout policies..."

    #get the current security config into a text file
    secedit /export /cfg C:\temp_sec.cfg

    #load that file into the below varaible
    $policy = Get-Content C:\temp_sec.cfg

    #replaces values in the variable with ones that improve security
    $policy = $policy `
        -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 14" `      #set min pw lenth to 14
        -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24" `          #set pw history to 24
        -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 30" `            #set max pw age to be 30
        -replace "LockoutBadCount = \d+", "LockoutBadCount = 5"                     #set account lockout after 5 failed pw attempts

    #overwrite the config file
    $policy | Out-File C:\temp_sec.cfg -Encoding ASCII

    #apply the changes to windows OS
    secedit /configure `
        /db C:\Windows\security\local.sdb `
        /cfg C:\temp_sec.cfg `
        /quiet
}
set_password_policy


# enable windows firewall
function enable_firewall {
    Write-Host "Enabling Windows Firewall..."

    #enable firewall across all network types
    Set-NetFirewallProfile `
        -Profile Domain,Public,Private `
        -Enabled True
}
enable_firewall


# configure audit policies
function configure_audit_policy {
    Write-Host "Configuring audit policies..."

    auditpol /set /category:"Account Logon"    /success:enable /failure:enable      #log authentication attempts
    auditpol /set /category:"Account Management" /success:enable /failure:enable    #log changes to users/groups etc
    auditpol /set /category:"Logon/Logoff"     /success:enable /failure:enable      #log any logins and locks/unlocks
    auditpol /set /category:"Object Access"    /success:disable /failure:enable     #log any file access failures
    auditpol /set /category:"Process Creation" /success:enable /failure:disable     #log any new esecuted processes
}
configure_audit_policy


# enable powerShell logging
function enable_powershell_logging {
    Write-Host "Enabling PowerShell logging..."

    #creates the registry path if its missing
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -ErrorAction SilentlyContinue | Out-Null
    #sdds a DWORD registry value of 1 which logs every powershell script block. helps to catch malware
    New-ItemProperty `
        -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" `
        -Value 1 `
        -PropertyType DWORD `
        -Force
}
enable_powershell_logging


# remove bloatware 
function remove_bloatware {
    Write-Host "Removing common bloatware..."
    #create a list of some consumer software that isnt necessary in enterprise endpoints
    $bloat = @(
        "Microsoft.XboxApp",
        "Microsoft.3DBuilder",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.SkypeApp"
    )
    #finds them in the windows store and uninstalls them
    foreach ($app in $bloat) {
        Write-Host "    - Removing $app"
        Get-AppxPackage *$app* | Remove-AppxPackage -ErrorAction SilentlyContinue
    }
}
remove_bloatware


# disable autologin
function disable_autologin {
    Write-Host "Ensuring auto-logon is disabled..."
    #deletes the registry key used to auto login a user
    Remove-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        -Name "AutoAdminLogon" `
        -ErrorAction SilentlyContinue
}
disable_autologin

#finished
Write-Host "===== HARDENING COMPLETE =====" -ForegroundColor Green
