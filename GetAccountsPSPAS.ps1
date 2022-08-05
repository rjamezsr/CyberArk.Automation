#region About GetAccountsPSPAS.ps1
###########################################################################
# This script connects to CyberArk REST API and gets account data
#


###########################################################################
#>
#endregion
param (
    [Parameter(Mandatory=$false,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL="",

    #[String]$PVWAURL="https://cyberarkdemo.westus.cloudapp.azure.com/PasswordVault",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the safe name")]
	[String]$TargetSafe="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the folder name")]
	[String]$TargetFolder="",
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter the file path for the report")]
	[String]$sourcepath="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the name of the safe to store the report")]
	[String]$Reports_Safe="",

    [Parameter(Mandatory=$false,HelpMessage="Please enter the name of the safe folder to store the report")]
	[String]$Reports_Folder="",

    [Parameter(Mandatory=$false,HelpMessage="Please specify if the report will be force created (re-created) if exists")]
	[String]$ForceReportCreation="",

    [Parameter(Mandatory=$false)]
    [String]$authtoken,

    [Parameter(Mandatory=$false)]
    [String]$authtype="",
    
    [Parameter(Mandatory=$false)]
    [String]$safeListRef="",
    

    [Parameter(Mandatory=$false)]
    [String]$ConfigPath="SampleGetAccountsConfig.json"
    
    
)
. '.\Common.ps1'

function EnumerateResults {
    param($TargetSafe)
    $results = $null
    $nextLink = $null
    $rows = 0
    $results = Get-PASAccount -safeName $TargetSafe
    if($null -ne $results){
        $rows = ($results | measure).Count
        LogMessage -message "**********************************"
        LogMessage -message "**********************************"
        LogMessage -message "$rows = rows returned for '$GetAccountsURI'"
        LogMessage -message "**********************************"
        LogMessage -message "**********************************"
    }else{
        LogMessage -message "**********************************"
        LogMessage -message "**********************************"
        LogMessage -message "0 = rows returned for '$GetAccountsURI'"
        LogMessage -message "**********************************"
    }
    [void]$ResultsCollection.Add($results)
    $nextLink = $results.nextLink
    <#
    if($null -ne $nextLink){
        EnumerateResults -AuthZHeader $AuthZHeader -TargetSafe $TargetSafe -urlSuffix $nextLink
    }
    #>
}
function ConvertUnixTime {
    param($seconds)
    $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    $ret = $origin.AddSeconds($seconds)
    $ret
}

function Get-SafesPSPAS {
    param($SafeName,[switch]$UseGen1)

    try {
        if($UseGen1){
            Get-PASSafe -UseGen1API -SafeName $SafeName
        }else{
            Get-PASSafe -SafeName $SafeName
        }
    }catch{
        LogError -message $Error[0]
    }

}



$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName


$ConfigFileExists = Test-Path $ConfigPath
$SuppliedCredentials = $false

if($null -ne $Usr -and $Usr.Length -ne 0 -and $null -ne $PwdC -and $PwdC.Length -ne 0){
    $SuppliedCredentials = $true
}

if($ConfigFileExists -eq $false -and $SuppliedCredentials -eq $false){
    LogMessage -message "Credentials were not provided and there is no config file or config file does not exist. Config file path '$ConfigPath'"
    LogMessage -message "Aborting"
    return
}

if($ConfigFileExists){
    $configContent = LoadJSONConfig -configpath $ConfigPath
    $config = $configContent.GetAccountsPSPAS
    $VaultConfig = $configContent.VaultAuthorization
    $RESTAPIConfig = $config.RESTAPI
    LogMessage -message "Config file loaded '$ConfigPath'"
}else{
    LogMessage -message "No config file specified or config file does not exist."
}

if($SuppliedCredentials){
    LogMessage -message "Overriding configuration for vault credentials. Using supplied credential."
    $appUsr = $Usr
}else{
    LogMessage -message "No credential override was supplied. Using credentials configured in the configuration file."
}

if($null -eq $config -or $null -eq $VaultConfig){
    LogError -message "Could not load config file '$ConfigPath'"
    return
}

$Token = $null

if($SuppliedCredentials -eq $false){
    LogMessage -message "Getting pacli credentials from vault"
    #get app user cred
    $appUserCred = $null
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
    
    if($null -eq $appUserCred.Password) {
        LogError -message "Could not get report app user credential! Aborting." 
        return
    }
    
    $appUsr = $VaultConfig.user.Trim()
    $AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy
    $AppPwdC = $AppPwdC.Replace(" ","") 
    $PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force

}

$AuthZHeader = $null

if($null -eq $PVWAURL -or $PVWAURL.Length -eq 0){
    LogMessage -message "No URL override provided. Checking config."
    if($null -eq $config.RESTAPI.BaseURL -or $config.RESTAPI.BaseURL.Length -eq 0){
        LogMessage -message "No URL override provided nor defined in a config. Aborting."
        return
    }else{

        $PVWAURL = $config.RESTAPI.BaseURL
        $authtype = $config.RESTAPI.authtype
        $LogonUri = $PVWAURL+"/PasswordVault/API/auth/$authtype/Logon"
        LogMessage -message "PVWAURL provided by config '$PVWAURL'"   
    }
}else{
    LogMessage -message "PVWAURL override provided."   
}
<#
$Token = GetAuthorizationToken -Usr $appUsr -Pwd $PwdC -cyberarkLogonUrl $LogonUri
if($null -eq $Token){
    if($null -ne $authtoken -and $authtoken.Length -ne 0){
        LogMessage -message "Token not supplied through configuration. Using token supplied by user."
        $AuthZHeader = GetAuthorizationTokenHeader -token $authtoken
    }else{
        LogMessage -message "Token not supplied through configuration nor supplied by user. Prompting for authentication.."
        $AuthZHeader = GetAuthorizationTokenHeader -token $null
    }
    
}else{
    LogMessage -message "Token supplied through configuration."
    $AuthZHeader = GetAuthorizationTokenHeader -token $Token
}
#>
[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)


$TargetSafes = $null
if($null -eq $TargetSafe -or $TargetSafe.Length -eq 0){
    LogMessage -message "No target safe override provided. Checking config."
    if($null -eq $config.Safes){
        LogMessage -message "No target safe override provided nor configured. Aborting."
        return
    }else{
        LogMessage -message "Target safes are configured. Using config file."
        $TargetSafes = $config.Safes
    }

}else{
    LogMessage -message "Target safe override provided."
    $TargetSafes = @([PSCustomObject]@{
        TargetSafe = $TargetSafe;
        TargetFolder = $TargetSafe;
        sourcepath = $sourcepath;
        Reports_Safe = $Reports_Safe;
        Reports_Folder = $Reports_Folder;
        ForceReportCreation = $ForceReportCreation;
    })
}


<#
if($null -eq $AuthZHeader){
    LogMessage -message "Could not get Authorization header. Aborting."
    return
}else{
    LogMessage -message "Generated authorization header successfully."
}
#>


if($null -eq $TargetSafes){
    LogMessage -message "Could not get target safe information. Aborting."
    return
}

$SafeListReference = $config.SafeListReference
if($safeListRef.Length -gt 0){
    LogMessage -message "Safe List reference override provided."
    $SafeListReference = $safeListRef
}else{
    LogMessage -message "No Safe List reference override provided. Using config."
    if($null -eq $SafeListReference -or $SafeListReference.Length -eq 0){
        LogMessage -message "No Safe List reference override provided NOR configured. Aborting."
        return
    }
}



$TargetSafes | Foreach-Object {
    
    $SafeName               = $null
    $UseGen1PSPAS           = $_.UseGen1Api -eq "Yes"
    $Folder                 = $null
    $Attributes             = $null
    $sourcepath             = $null
    $ForceReportCreation    = $null
    $SafeName               = $_.TargetSafe
    $Folder                 = $_.TargetFolder
    $sourcepath             = $_.sourcepath
    $ForceReportCreation    = $_.ForceReportCreation
    $ResultsCollection      = [System.Collections.ArrayList]@()
    $IgnoreSafes            = $_.IngoreSafes
    $ReportSafe             = $_.Reports_Safe
    $ReportFolder           = $_.Reports_Folder

    $GetSafesListURI = $PVWAURL+'/PasswordVault/api/safes?search={0}&limit=100000'
    $GetSafesListURI = $GetSafesListURI -f $SafeName
    #$SafesListFull   = GetSafesList -authZtoken $AuthZHeader -TargetSafe $SafeName -cyberarkGetSafesURL $GetSafesListURI
    New-PASSession -Credential $cred -BaseURI $PVWAURL


    if($UseGen1PSPAS){
        $SafesListFull   = Get-SafesPSPAS -UseGen1 -SafeName $SafeName
    }else{
        $SafesListFull   = Get-SafesPSPAS -SafeName $SafeName
    }

    

    if($null -ne $IgnoreSafes -and $IgnoreSafes -ne ""){
        $SafesList       = $SafesListFull | Where safeName -notlike "*$IgnoreSafes*"
    }else{
        $SafesList       = $SafesListFull
    }
    
    

    $FileExists = Test-Path $sourcepath
    $ForceFileCreation = $ForceReportCreation -eq "Yes"

    if($FileExists -eq $true -and $ForceFileCreation -eq $false){
        LogMessage -message "File exists and ForceReportCreation is NOT YES. Skipping safe '$SafeName'."
    }
    if($FileExists -and $ForceFileCreation -eq $true){
        Remove-Item -Path $sourcepath
    }


    $NumberOfSafes = 0
    $NumberOfSafes = ($SafesList | measure).Count

    if($NumberOfSafes -eq 0){
        LogMessage -message "No safes were found matching '$SafeName'"
    }
    if($NumberOfSafes -gt 0){
        
        $SafesList | Select safeName | ForEach-Object {
            $ResultsCollection      = [System.Collections.ArrayList]@()
            $TargetSafeName = $_.safeName
            LogMessage -message "Generating report for safe '$TargetSafeName'."
            
            $GetAccountsURI = $PVWAURL+'/api/Accounts?filter=safeName eq {0}&offset=1&limit=1'
            $GetAccountsURI = $GetAccountsURI -f $TargetSafeName

            EnumerateResults -AuthZHeader $AuthZHeader -TargetSafe $TargetSafeName -offset 0 -limit 1000


            $ResultsCollection | ForEach-Object {
                $Accounts = $_
                $ReportColumns = [System.Collections.ArrayList]@()
            
                [void]$ReportColumns.Add(@{Name="userName";expression={$_.userName}})
                [void]$ReportColumns.Add(@{Name="address";expression={$_.address}})
                [void]$ReportColumns.Add(@{Name="ip";expression={$_.ip}})
                [void]$ReportColumns.Add(@{Name="secretType";expression={$_.secretType}})
                [void]$ReportColumns.Add(@{Name="safeName";expression={$_.safeName}})
                [void]$ReportColumns.Add(@{Name="platformId";expression={$_.platformId}})
                
                
                #[void]$ReportColumns.Add(@{Name="createdTime";expression={$_.createdTime}})
                [void]$ReportColumns.Add(@{Name="createdTime";expression={ConvertUnixTime -seconds $_.createdTime}})

                [void]$ReportColumns.Add(@{Name="id";expression={$_.id}})
                [void]$ReportColumns.Add(@{Name="name";expression={$_.name}})
                [void]$ReportColumns.Add(@{Name="AccountCategory";expression={$_.platformAccountProperties.AccountCategory}})
                
                
                #[void]$ReportColumns.Add(@{Name="AccountDiscoveryDate";expression={$_.platformAccountProperties.AccountDiscoveryDate}})
                [void]$ReportColumns.Add(@{Name="AccountDiscoveryDate";expression={ConvertUnixTime -seconds $_.platformAccountProperties.AccountDiscoveryDate}})
                

                [void]$ReportColumns.Add(@{Name="AccountEnabled";expression={$_.platformAccountProperties.AccountEnabled}})
                [void]$ReportColumns.Add(@{Name="AccountExpirationDate";expression={$_.platformAccountProperties.AccountExpirationDate}})
                [void]$ReportColumns.Add(@{Name="AccountOSGroups";expression={$_.platformAccountProperties.AccountOSGroups}})
                [void]$ReportColumns.Add(@{Name="AccountType";expression={$_.platformAccountProperties.AccountType}})
                [void]$ReportColumns.Add(@{Name="Comment";expression={$_.platformAccountProperties.Comment}})
                [void]$ReportColumns.Add(@{Name="CreationMethod";expression={$_.platformAccountProperties.CreationMethod}})
                [void]$ReportColumns.Add(@{Name="DiscoveryPlatformType";expression={$_.platformAccountProperties.DiscoveryPlatformType}})
                [void]$ReportColumns.Add(@{Name="Fingerprint";expression={$_.platformAccountProperties.Fingerprint}})
                [void]$ReportColumns.Add(@{Name="GID";expression={$_.platformAccountProperties.GID}})
                [void]$ReportColumns.Add(@{Name="LastLogonDate";expression={$_.platformAccountProperties.LastLogonDate}})
                [void]$ReportColumns.Add(@{Name="LastPasswordSetDate";expression={$_.platformAccountProperties.LastPasswordSetDate}})
                [void]$ReportColumns.Add(@{Name="MachineOSFamily";expression={$_.platformAccountProperties.MachineOSFamily}})
                [void]$ReportColumns.Add(@{Name="OSVersion";expression={$_.platformAccountProperties.OSVersion}})
                [void]$ReportColumns.Add(@{Name="PasswordNeverExpires";expression={$_.platformAccountProperties.PasswordNeverExpires}})
                [void]$ReportColumns.Add(@{Name="Path";expression={$_.platformAccountProperties.Path}})
                [void]$ReportColumns.Add(@{Name="UID";expression={$_.platformAccountProperties.UID}})
                [void]$ReportColumns.Add(@{Name="automaticManagementEnabled";expression={$_.platformAccountProperties.automaticManagementEnabled}})
                
                #[void]$ReportColumns.Add(@{Name="lastModifiedTime";expression={$_.platformAccountProperties.lastModifiedTime}})
                [void]$ReportColumns.Add(@{Name="lastModifiedTime";expression={ConvertUnixTime -seconds $_.platformAccountProperties.lastModifiedTime}})
                
                

                $FileExists = Test-Path $sourcepath
                if($FileExists){
                    $Accounts | Select -Property $ReportColumns | Export-CSV $sourcepath -Append -NoTypeInformation
                }else{
                    $Accounts | Select -Property $ReportColumns | Export-CSV $sourcepath -NoTypeInformation
                }
            }
            
        }
        
    }

    Close-PASSession

    $filetoUpload = $sourcepath
    $filetoUploadExists = $false
    if($null -ne $filetoUpload -and $filetoUpload -ne ""){
        $filetoUploadExists = Test-Path $filetoUpload
    }
    if($filetoUploadExists){
        if($null -ne $ReportSafe -and $ReportSafe -ne ""){
            #Move file to safe
            LogMessage -message "File created. Now moving file to vault"
            $uploadPath = (Get-ChildItem -Path $filetoUpload).FullName
            PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                -Usr $appUsr `
                -password $PwdC -AsSecureString `
                -VaultAddress $VaultConfig.vaultip `
                -sessionid $VaultConfig.sessionid `
                -PACLI_EXE $VaultConfig.pacliexe `
                -TargetFolder $ReportFolder `
                -TargetSafe $ReportSafe `
                -inputpath $uploadPath

            Remove-Item $filetoUpload 
        }
    }
}



