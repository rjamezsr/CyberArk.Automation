#region About GetSafesListReport_RESTAPI.ps1
###########################################################################
# This script connects to CyberArk REST API and gets Safe data
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
    [String]$ConfigPath="Sample_GetSafesListReportRESTAPI_Config.json"
    
    
)
. '.\Common.ps1'
function EnumerateResults {
    param($url)
    $results = $null
    $rows = 0
    $results = GetSafeDetails -authZtoken $AuthZHeader -TargetSafe "" -cyberarkGetSafesURL $url
    $results.value | ForEach-Object {
        [void]$ResultsCollection.Add($_)
    }
}

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"

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
    $config = LoadJSONConfig -configpath $ConfigPath
    $VaultConfig = $config.VaultAuthorization
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

if($null -eq $config -or $config.Length -eq 0 -or $null -eq $VaultConfig -or $VaultConfig.Length -eq 0){
    LogError -message "Could not load config file '$AccountsFeedConfigPath'"
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
        -reason "Get app account for Sync Account Discovery List script" -autoChangePassword $true
    
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
        $LogonUri = $PVWAURL+"/API/auth/$authtype/Logon"
        LogMessage -message "PVWAURL provided by config '$PVWAURL'"   
    }
}else{
    LogMessage -message "PVWAURL override provided."   
}

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

$TargetSafes = $null
if($null -eq $TargetSafe -or $TargetSafe.Length -eq 0){
    LogMessage -message "No target safe override provided. Checking config."
    if($null -eq $config.GetSafesListReportRESTAPI.Safes){
        LogMessage -message "No target safe override provided nor configured. Aborting."
        return
    }else{
        LogMessage -message "Target safes are configured. Using config file."
        $TargetSafes = $config.GetSafesListReportRESTAPI.Safes
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
if($null -eq $AuthZHeader){
    LogMessage -message "Could not get Authorization header. Aborting."
    return
}else{
    LogMessage -message "Generated authorization header successfully."
}
if($null -eq $TargetSafes){
    LogMessage -message "Could not get target safe information. Aborting."
    return
}
$SafeListReference = $config.GetSafesListReportRESTAPI.SafeListReference
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
$IncludeEmptySafes_config = $config.GetSafesListReportRESTAPI.IncludeEmptySafes
$IncludeEmptySafes = ($IncludeEmptySafes_config -eq "Yes")
$GetSafesListURI = $PVWAURL+'/api/safes?extendedDetails=false&limit=1000'
$GetSafesListURI = $GetSafesListURI -f $SafeName
$AllSafesList  = GetSafesList -authZtoken $AuthZHeader -TargetSafe $SafeName -cyberarkGetSafesURL $GetSafesListURI
$TargetSafes | Foreach-Object {
    $SafeName               = $null
    $Folder                 = $null
    $Attributes             = $null
    $sourcepath             = $null
    $ForceReportCreation    = $null
    $SafeName               = $_.TargetSafe
    $SafeNameRegEx          = $_.SafeNameRegEx
    $Folder                 = $_.TargetFolder
    $sourcepath             = $_.sourcepath
    $ForceReportCreation    = $_.ForceReportCreation
    $ResultsCollection      = [System.Collections.ArrayList]@()
    $SafesList = $null
    if($null -ne $SafeNameRegEx -and $SafeNameRegEx -ne ""){
        $SafesList = $AllSafesList.$SafeListReference | Where SafeName -match $SafeNameRegEx | Select SafeName
    }else{
        $SafesList = $AllSafesList.$SafeListReference | Where SafeName -like $SafeName | Select SafeName
    }
    $FileExists = Test-Path $sourcepath
    $ForceFileCreation = $ForceReportCreation -eq "Yes"
    if($FileExists -eq $true -and $ForceFileCreation -eq $false){
        LogMessage -message "File exists and ForceReportCreation is NOT YES for '$SafeName'."
    }
    if($FileExists -and $ForceFileCreation -eq $true){
        Remove-Item -Path $sourcepath
    }
    if($SafesList.Length -eq 0){
        LogMessage -message "No safes were found matching '$SafeName'"
    }
    if($SafesList.Length -gt 0){
        $SafesList | Select safeName | ForEach-Object {
            $ResultsCollection      = [System.Collections.ArrayList]@()
            $TargetSafeName = $_.safeName
            $GetSafeDetailsURI = $PVWAURL+'/api/safes?search={0}&extendedDetails=true&includeAccounts=true'
            $GetSafeDetailsURI = $GetSafeDetailsURI -f $TargetSafeName
            EnumerateResults -url $GetSafeDetailsURI
            $ResultsCollection | ForEach-Object {
                $results = $_
                if($results.safeName -eq $TargetSafeName){
                     $numberOfAccounts = ($results | select accounts).accounts.Length
                    $creator = ($results | select creator).creator.name
                    $ReportColumns = [System.Collections.ArrayList]@()
                    if(($numberOfAccounts -eq 0 -and $IncludeEmptySafes -eq $true) -or ($numberOfAccounts -gt 0)){
                        LogMessage -message "Generating report for safe '$TargetSafeName'."
                        [void]$ReportColumns.Add(@{Name="safeUrlId";expression={$results.safeUrlId}})
                        [void]$ReportColumns.Add(@{Name="safeName";expression={$results.safeName}})
                        [void]$ReportColumns.Add(@{Name="safeNumber";expression={$results.safeNumber}})
                        [void]$ReportColumns.Add(@{Name="description";expression={$results.description}})
                        [void]$ReportColumns.Add(@{Name="location";expression={$results.location}})
                        [void]$ReportColumns.Add(@{Name="olacEnabled";expression={$results.olacEnabled}})
                        [void]$ReportColumns.Add(@{Name="managingCPM";expression={$results.managingCPM}})
                        [void]$ReportColumns.Add(@{Name="numberOfVersionsRetention";expression={$results.numberOfVersionsRetention}})
                        [void]$ReportColumns.Add(@{Name="numberOfDaysRetention";expression={$results.numberOfDaysRetention}})
                        [void]$ReportColumns.Add(@{Name="autoPurgeEnabled";expression={$results.autoPurgeEnabled}})
                        [void]$ReportColumns.Add(@{Name="creationTime";expression={$results.creationTime}})
                        [void]$ReportColumns.Add(@{Name="lastModificationTime";expression={$results.lastModificationTime}})
                        [void]$ReportColumns.Add(@{Name="isExpiredMember";expression={$results.isExpiredMember}})
                        [void]$ReportColumns.Add(@{Name="creator";expression={$creator}})
                        [void]$ReportColumns.Add(@{Name="numberOfAccounts";expression={$numberOfAccounts}})
                        $FileExists = Test-Path $sourcepath
                        if($FileExists){
                            $results | Select -Property $ReportColumns | Export-CSV $sourcepath -Append -NoTypeInformation
                        }else{
                            $results | Select -Property $ReportColumns | Export-CSV $sourcepath -NoTypeInformation
                        }
                    }
                }else{
                    $skippedSafe = $_.safeName
                    LogMessage -message "Safe name '$TargetSafeName' does not match safe name returned from safe details '$skippedSafe'"
                }
            }
        }
    }
    if($null -ne $_.Reports_Safe -and $_.Reports_Safe.Length -ne 0){
        LogMessage -message "File created. Now moving file to vault"
        PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
            -Usr $appUsr `
            -password $PwdC -AsSecureString `
            -VaultAddress $VaultConfig.vaultip `
            -sessionid $VaultConfig.sessionid `
            -PACLI_EXE $VaultConfig.pacliexe `
            -TargetFolder $_.Reports_Folder `
            -TargetSafe $_.Reports_Safe `
            -inputpath $_.sourcepath

        Remove-Item $_.sourcepath
    }
    
}
