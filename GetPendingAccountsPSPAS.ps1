#region About GetPendingAccountsPSPAS.ps1
###########################################################################
# This script reads object data from the PasswordManager_Pending safe and stores it in a CSV file
#
#endregion
param (

    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid Config file path")]
	[String]$ConfigPath="Sample_GetPendingAccountsPSPAS_Config.json"
    
)

. '.\Common.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName
$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$config = (LoadJSONConfig -configpath $ConfigPath)

if($config.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 
}

$outputpath  = $config.GetPendingAccountsPSPAS.sourcepath
$PullData = $true

$OutputFileExists = Test-Path $outputpath
if($OutputFileExists -and $config.GetPendingAccountsPSPAS.ForceReportCreation -eq "Yes"){
    Remove-Item $outputpath 
}

$appUserCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
    -user $VaultConfig.gwuser `
    -logonfile $VaultConfig.logonfile `
    -sessionid $VaultConfig.sessionid `
    -vaultip $VaultConfig.vaultip `
    -pacliexe $VaultConfig.pacliexe `
    -targetsafe $VaultConfig.gwusersafe `
    -folder $VaultConfig.gwuserfolder `
    -objectname $VaultConfig.gwuserobjectname `
    -reason "Executing $Executing as user $currentUser" -autoChangePassword $true

if($null -eq $appUserCred) {
    LogError -message "Could not get report app user credential!" 
    Throw "Could not get report app user credential!"  
    return
}

$appUsr = $VaultConfig.user.Trim()
$AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
$AppPwdC = $AppPwdC.Replace(" ","") 
$PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force
[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)
New-PASSession -Credential $cred -BaseURI $config.GetPendingAccountsPSPAS.RESTAPI.BaseURI

$config.GetPendingAccountsPSPAS.filters | ForEach-Object {

    $filter = $_
    $pendingAccountData = Get-PASDiscoveredAccount -platformType $filter.platformType 
    $pendingAccountData | Foreach-Object {
        $Accounts = $_
        $ReportColumns = [System.Collections.ArrayList]@()
        [void]$ReportColumns.Add(@{Name="id";expression={$_.id}})
        [void]$ReportColumns.Add(@{Name="Filename";expression={$_.name}})
        [void]$ReportColumns.Add(@{Name="Name";expression={$_.name}})
        [void]$ReportColumns.Add(@{Name="userName";expression={$_.userName}})
        [void]$ReportColumns.Add(@{Name="address";expression={$_.address}})
        [void]$ReportColumns.Add(@{Name="AccountDiscoveryDate";expression={$_.discoveryDateTime}})
        [void]$ReportColumns.Add(@{Name="accountEnabled";expression={$_.accountEnabled}})
        [void]$ReportColumns.Add(@{Name="AccountOSGroups";expression={$_.osGroups}})
        [void]$ReportColumns.Add(@{Name="DiscoveryPlatformType";expression={$_.platformType}})
        [void]$ReportColumns.Add(@{Name="domain";expression={$_.domain}})
        [void]$ReportColumns.Add(@{Name="LastLogonDate";expression={$_.lastLogonDateTime}})
        [void]$ReportColumns.Add(@{Name="LastPasswordSetDate";expression={$_.lastPasswordSetDateTime}})
        [void]$ReportColumns.Add(@{Name="passwordNeverExpires";expression={$_.passwordNeverExpires}})
        [void]$ReportColumns.Add(@{Name="osVersion";expression={$_.osVersion}})
        [void]$ReportColumns.Add(@{Name="privileged";expression={$_.privileged}})
        [void]$ReportColumns.Add(@{Name="description";expression={$_.description}})
        [void]$ReportColumns.Add(@{Name="AccountExpirationDate";expression={$_.passwordExpirationDateTime}})
        [void]$ReportColumns.Add(@{Name="osFamily";expression={$_.osFamily}})
        [void]$ReportColumns.Add(@{Name="OU";expression={$_.organizationalUnit}})
        [void]$ReportColumns.Add(@{Name="CreationMethod";expression={$_.additionalProperties.CreationMethod}})
        [void]$ReportColumns.Add(@{Name="AccountType";expression={$_.additionalProperties.AccountType}})
        [void]$ReportColumns.Add(@{Name="SID";expression={$_.platformTypeAccountProperties.SID}})

        [void]$ReportColumns.Add(@{Name="UID";expression={$_.platformTypeAccountProperties.UID}})
        [void]$ReportColumns.Add(@{Name="GID";expression={$_.platformTypeAccountProperties.GID}})
        [void]$ReportColumns.Add(@{Name="Path";expression={$_.platformTypeAccountProperties.Path}})
        [void]$ReportColumns.Add(@{Name="Format";expression={$_.platformTypeAccountProperties.Format}})
        [void]$ReportColumns.Add(@{Name="Comment";expression={$_.platformTypeAccountProperties.Comment}})
        [void]$ReportColumns.Add(@{Name="DeviceType";expression={$_.additionalProperties.DeviceType}})

        <#

        [void]$ReportColumns.Add(@{Name="AccountCategory";expression=""})
        [void]$ReportColumns.Add(@{Name="MachineOSFamily";expression=""})
        [void]$ReportColumns.Add(@{Name="Dependencies";expression=""})
        [void]$ReportColumns.Add(@{Name="UserDisplayName";expression=""})
        
        
        [void]$ReportColumns.Add(@{Name="Fingerprint";expression=""})
        [void]$ReportColumns.Add(@{Name="Length";expression=""})
        [void]$ReportColumns.Add(@{Name="Path";expression=""})
        [void]$ReportColumns.Add(@{Name="Format";expression=""})
        [void]$ReportColumns.Add(@{Name="Comment";expression=""})
        [void]$ReportColumns.Add(@{Name="Encryption";expression=""})
        [void]$ReportColumns.Add(@{Name="DeviceType";expression=""})
        [void]$ReportColumns.Add(@{Name="Safe";expression="PasswordManager_Pending"})
        [void]$ReportColumns.Add(@{Name="folder";expression="root"})
        [void]$ReportColumns.Add(@{Name="TargetSafeName";expression=""})
        [void]$ReportColumns.Add(@{Name="TargetPlatformId";expression=""})

        #>
   
        $FileExists = Test-Path $outputpath
        if($FileExists){
            $Accounts | Select -Property $ReportColumns | Export-CSV $outputpath -Append -NoTypeInformation -Force
        }else{
            $Accounts | Select -Property $ReportColumns | Export-CSV $outputpath -NoTypeInformation
        }

    }

}

Close-PASSession

if($null -ne $config.GetPendingAccountsPSPAS.Reports_Safe -and $config.GetPendingAccountsPSPAS.Reports_Safe.Length -ne 0){
    #Move file to safe
    LogMessage -message "File created. Now moving file to vault"
    PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
        -Usr $appUsr `
        -password $PwdC -AsSecureString `
        -VaultAddress $VaultConfig.vaultip `
        -sessionid $VaultConfig.sessionid `
        -PACLI_EXE $VaultConfig.pacliexe `
        -TargetFolder $config.GetPendingAccountsPSPAS.Reports_Folder `
        -TargetSafe $config.GetPendingAccountsPSPAS.Reports_Safe `
        -inputpath $outputpath
}

