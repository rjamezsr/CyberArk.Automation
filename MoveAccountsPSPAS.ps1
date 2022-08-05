#region About MoveAccountsPSPAS.ps1
###########################################################################
# This script connects to CyberArk REST API and moves account data
#


###########################################################################
#>
#endregion
param (
    [Parameter(Mandatory=$false)]
    [String]$ConfigPath="Sample.MoveAccountsPSPAS.Config.json"
)
. '.\Common.ps1'
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

$ConfigFileExists    = Test-Path $ConfigPath
$SuppliedCredentials = $false
$FilesToUpload       = [System.Collections.ArrayList]@()

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
    $config = $configContent.MoveAccountsPSPAS
    $VaultConfig = $configContent.VaultAuthorization
    $PVWAURL = $config.RESTAPI.BaseURL
    $MaxInterval = [int]$config.MaxIntervals
    $WaitIntervalInSeconds = [int]$config.WaitIntervalInSeconds
    $OutputDirectory = $config.OutputDirectory
    $OutputSafeName = $config.OutputSafeName
    $OutputSafeFolder = $config.OutputSafeFolder
    LogMessage -message "PVWAURL provided by config '$PVWAURL'"  
    LogMessage -message "Config file loaded '$ConfigPath'"
}else{
    LogMessage -message "No config file specified or config file does not exist."
}


if($configContent.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 
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
if($null -eq $MaxInterval){
    LogError -message "MaxInterval not set."
    return
}
if($null -eq $WaitIntervalInSeconds){
    LogError -message "WaitIntervalInSeconds not set."
    return
}
if($null -eq $OutputDirectory){
    LogError -message "OutputDirectory not set."
    return
}else{
    if(Test-Path $OutputDirectory){
    }else{
        LogError -message "OutputDirectory '$OutputDirectory' does not exist."
        return
    }
}
LogMessage -message "Getting pacli credentials from vault"
$appUserCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
    -user $VaultConfig.gwuser `
    -logonfile $VaultConfig.logonfile `
    -sessionid $VaultConfig.sessionid `
    -vaultip $VaultConfig.vaultip `
    -pacliexe $VaultConfig.pacliexe `
    -targetsafe $VaultConfig.gwusersafe `
    -folder $VaultConfig.gwuserfolder `
    -objectname $VaultConfig.gwuserobjectname `
    -reason ("Executing {0} as user {1}" -f $MyInvocation.MyCommand.Name,$env:UserName) `
    -autoChangePassword $true
if($null -eq $appUserCred.Password) {
    LogError -message "Could not get report app user credential! Aborting." 
    return
}
$appUsr = $VaultConfig.user.Trim()
$AppPwdC = $appUserCred.Password[1]
$AppPwdC = $AppPwdC.Replace(" ","") 
$PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force
[pscredential]$cred = New-Object System.Management.Automation.PSCredential ($appUsr, $PwdC)
New-PASSession -Credential $cred -BaseURI $PVWAURL
$config.TargetSafes | Foreach-Object {
    $Enabled                = $_.Enabled -eq "true"
    $TargetSafe             = $_.TargetSafe
    $sourcepath             = $_.sourcepath
    $DeleteSourceFile       = $_.DeleteSourceFile -eq "Yes"
    $TargetPlatformId       = $_.TargetPlatformId
    $UseGen1PSPAS           = $_.UseGen1Api -eq "Yes"
    $SafeExists             = $false
    $PlatformExists         = $false
    $SourceFileExists       = $false
    $SourceData             = $null
    $AccountData            = $null
    $ResultsCollection      = [System.Collections.ArrayList]@()
    $ImportJob              = $null
    $NumAccountsCopied      = 0
    $NumAccountsDeleted     = 0
    $NumOfAccountsToMove    = 0
    $PlatformSet            = $false
    if($null -eq $TargetPlatformId -or $TargetPlatformId -eq ""){
        LogMessage -message "TargetPlatformId not set. Using platform on incoming account."
        $Enabled = $false
    }
    if($null -eq (Get-PASPlatform -PlatformID $TargetPlatformId)){
        LogMessage -message "TargetPlatformId does not exist."
        $Enabled = $false
    }
    if($null -eq $TargetSafe){
        LogMessage -message "TargetSafe not set."
        $Enabled = $false
    }
    if($null -eq (Get-PASSafe -UseGen1API -SafeName $TargetSafe)){
        LogMessage -message "TargetSafe does not exist."
        $Enabled = $false
    }
    if($null -ne $sourcepath -and $sourcepath -ne ""){
        $SourceFileExists = Test-Path -Path $sourcepath
    }
    if($SourceFileExists){
        $archiveSourceFilePath = Join-Path -Path (Split-Path -Path $sourcepath -Parent) -ChildPath ("{0}_{1}{2}" -f [System.IO.Path]::GetFileNameWithoutExtension($sourcepath),(get-date -Format MM-dd-yyyy),[System.IO.Path]::GetExtension($sourcepath))
        Copy-Item $sourcepath -Destination $archiveSourceFilePath -Force

        if($null -ne $OutputSafeName -and $OutputSafeName -ne ""){
            $FilesToUpload.Add($archiveSourceFilePath)
            <#
            LogMessage -message "Archive file '$ErrorFile' created. Now moving file to vault"
            PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                -Usr $VaultConfig.user `
                -password $PwdC -AsSecureString `
                -VaultAddress $VaultConfig.vaultip `
                -sessionid $VaultConfig.sessionid `
                -PACLI_EXE $VaultConfig.pacliexe `
                -TargetFolder $OutputSafeFolder `
                -TargetSafe $OutputSafeName `
                -inputpath $archiveSourceFilePath
            #>
            
        }




        $SourceData = Import-Csv $sourcepath
    }else{
        LogMessage -message "Source file '$sourcepath' does not exist. Skipping."
        $Enabled = $false
    }
    if($Enabled){
        
        $SourceData | Foreach-Object {
            $progress = Show_Progress -list $SourceData -progressObject $progress
            if($null -ne $_.id){
                $AccountData = Get-PASAccount -id $_.id
                if($null -ne $AccountData){
                    $AccountData.safeName = $TargetSafe
                    if($PlatformSet){
                        $AccountData.platformId = $TargetPlatformId
                    }
                    [void]$ResultsCollection.Add($AccountData) 
                }
            }else{
                LogMessage -message "Account data is missing the id value. Will not move."
            }
        }
        
        if(($ResultsCollection | Measure-Object).Count -eq 0){
            LogMessage -message "No accounts to move. Skipping."
        }else{
            $NumOfAccountsToMove = ($ResultsCollection | Measure-Object).Count
            LogMessage -message "Moving $NumOfAccountsToMove to safe '$TargetSafe'"



            $ImportJob = Start-PASAccountImportJob -accountsList $ResultsCollection
            if($null -ne $ImportJob){
                $ImportJobId = $ImportJob.Id
                $ImportJob = Get-PASAccountImportJob -id $ImportJobId
                $IntervalElapsed = 0
                $ImportStatus = ""
                $ImportStatus = $ImportJob.Status
                $ImportComplete = $false
                $progress = $null
                while($ImportComplete -eq $false)
                {
                    
                    Start-Sleep -Seconds $config.WaitIntervalInSeconds
                    LogMessage -message "Getttng import job status attempt $IntervalElapsed"
                    $ImportJob = Get-PASAccountImportJob -id $ImportJobId
                    $ImportStatus = $ImportJob.Status
                    $FailedItems = (($ImportJob | ConvertTo-Json) | ConvertFrom-Json).FailedItems.Total
                    Show_Progress -message "Moving $NumOfAccountsToMove records. Status is $ImportStatus (Failed items: $FailedItems)"
                    $IntervalElapsed = $IntervalElapsed + 1
                    $ImportComplete = $IntervalElapsed -eq $MaxInterval -or $ImportStatus -eq "Completed"
                    if($ImportStatus -ne "Completed" -and $ImportComplete){
                        LogMessage -message "Max intervals were reached. Import timed out"
                    }
                }
                $ImportJob = Get-PASAccountImportJob -id $ImportJobId
                $NumAccountsCopied = $ImportJob.SucceededItems.Total
                $RecordStatus = $null   
                if($ImportStatus -eq "Completed"){
                }else{
                    if($null -eq $NumAccountsCopied){
                        $RecordStatus = "Unknown"
                    }else{
                        $RecordStatus = $NumAccountsCopied
                    }
                    LogMessage -message "Import job was NOT successful. Status is '$ImportStatus' and number of accounts copied is $RecordStatus"
                    $ErrorFileName = [System.IO.Path]::GetFileNameWithoutExtension($sourcepath) + "_errors_" + (Get-Date -Format MM_dd_yyyy) + ".csv"
                    $ErrorFile = Join-Path -Path $OutputDirectory -ChildPath $ErrorFileName
                    if($null -eq $ImportJob.FailedItems.Items){
                        LogMessage -message "CyberArk did not return FailedItems report"
                    }else{
                        LogMessage -message "Generating error file '$ErrorFile'"
                        $ImportJob.FailedItems.Items | Export-Csv $ErrorFile -NoTypeInformation
                        if(Test-Path -Path $ErrorFile){
                            if($null -ne $OutputSafeName -and $OutputSafeName -ne ""){
                                #Move file to safe
                                
                                $FilesToUpload.Add($ErrorFile)

                                <#
                                LogMessage -message "File '$ErrorFile' created. Now moving file to vault"
                                PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                                    -Usr $VaultConfig.user `
                                    -password $PwdC -AsSecureString `
                                    -VaultAddress $VaultConfig.vaultip `
                                    -sessionid $VaultConfig.sessionid `
                                    -PACLI_EXE $VaultConfig.pacliexe `
                                    -TargetFolder $OutputSafeFolder `
                                    -TargetSafe $OutputSafeName `
                                    -inputpath $ErrorFile
                                if(Test-Path $ErrorFile){
                                    LogMessage -message "File '$ErrorFile' was not removed from local."
                                }
                                #>
                            }
                        }
                    }
                }
            }
            if($NumAccountsCopied -eq $NumOfAccountsToMove -and $NumOfAccountsToMove -gt 0){
                $SourceData | Foreach-Object {
                    $accountId = $_.id
                    Remove-PASAccount -AccountID $accountId
                    $NumAccountsDeleted = $NumAccountsDeleted + 1
                }
            }
        }
        if($NumAccountsCopied -eq $NumAccountsDeleted){
            LogMessage -message "$NumAccountsCopied accounts moved to safe '$TargetSafe'"
        }
        if($DeleteSourceFile -and $NumAccountsCopied -eq $NumAccountsDeleted -and $NumAccountsCopied -gt 0 -and $SourceFileExists){
            LogMessage -message "All accounts moved successfully. Deleting file '$sourcepath'"
            Remove-Item -Path $sourcepath
        }
    }
}
Close-PASSession

if($null -ne $OutputSafeName -and $OutputSafeName -ne "" -and $null -ne $OutputSafeFolder -and $OutputSafeFolder -ne ""){
    if(($FilesToUpload | Measure-Object).Count -gt 0){
        $FilesToUpload | ForEach-Object {
            $fileToUpload = $_
            LogMessage -message "Moving file '$fileToUpload' to vault"
            PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                -Usr $VaultConfig.user `
                -password $PwdC -AsSecureString `
                -VaultAddress $VaultConfig.vaultip `
                -sessionid $VaultConfig.sessionid `
                -PACLI_EXE $VaultConfig.pacliexe `
                -TargetFolder $OutputSafeFolder `
                -TargetSafe $OutputSafeName `
                -inputpath $fileToUpload
        }
    }
}