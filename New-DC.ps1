# Variables and Constants
$DcIp = '192.168.1.97'
$DcName = 'DC01'
$NewDomainName = 'chrimeny'
$LocalAdminName = 'Administrator'
$LocalAdminPwd = 'Pa$$w0rd'
$SecurePwd = ConvertTo-SecureString $LocalAdminPwd -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($LocalAdminName, $SecurePwd)

# Run this locally on the VM
$Splat = @{
    Path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' 
    Name = Shell 
    Value = 'PowerShell.exe'
}
Set-ItemProperty @Splat
Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
New-NetFirewallRule -DisplayName "Allow All" -Direction Inbound -Action Allow
Rename-Computer -NewName $DcName -Restart

# You can run this via a remote session or locally
# If run locally you need to only run what's in the scriptblocks
# The Invoke-Commands are unnecessary
Invoke-Command -ComputerName $DcIp -Credential $cred -ScriptBlock {
    Install-WindowsFeature –Name AD-Domain-Services -IncludeManagementTools

    $Splat = @{
        DomainName = "{0}.dev" -f $using:NewDomainName
        DatabasePath = "C:\Windows\NTDS"
        DomainMode = "7"
        DomainNetbiosName = "{0}" -f $($using:NewDomainName).ToUpper()
        ForestMode = "7"
        LogPath = "C:\Windows\NTDS"
        SysvolPath = "C:\Windows\SYSVOL"
        CreateDnsDelegation = $false 
        InstallDns = $true 
        Force = $true
    }
    Install-ADDSForest @Splat
}