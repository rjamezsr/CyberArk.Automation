#region About GetAccountManagementStatus_PSPAS.ps1
###########################################################################
# This script connects to CyberArk REST API and gets account data
# Detail includes PM status, history and age (as it relates to adding to current safe)


###########################################################################
#>
#endregion
param (
    [Parameter(Mandatory=$false)]
    [String]$ConfigPath="C:\\repo\\Azure.DevOps\\Prolab-IDM\\CyberArk.Automation.Config\\Manual\\GetAccountManagementStatus_PSPAS.json"
)
. '.\Common.ps1'
. '.\Common.Connect.ps1'
. '.\Common.Query.ps1'


function Enumerate-Results {
    param($TargetSafe)
    $results = $null
    $nextLink = $null
    
    $results = Get-PASAccount -safeName $TargetSafe
    
    $rows = ($results | measure).Count
    LogMessage -message "$rows = rows returned for '$TargetSafe'"
    $results | Foreach-Object {
        $progress = Show_Progress -progressObject $progress -list $results -message "Query safe $TargetSafe"
        $activity = Get-PASAccountActivity -AccountID $_.id
        $verifyStatus = Get-LastVerifiedStatus -activity $activity
        $changeStatus = Get-LastChangeStatus -activity $activity
        $reconStatus = Get-LastReconStatus -activity $activity
        $history = Get-AccountHistoryPasswordManagement -activity $activity
        $accountInfo = [pscustomobject]@{
            Info=$_;
            Detail=(Get-PASAccountDetail -id $_.id);
            History=$history;
            ManageUser = $history.Username
            VerifyStatus = $verifyStatus.status;
            VerifyStatusMessage = $verifyStatus.message;
            VerifyAttempt = $verifyStatus.time;

            ChangeStatus = $changeStatus.status;
            ChangeStatusMessage = $changeStatus.message;
            ChangeAttempt = $changeStatus.time;

            ReconStatus = $reconStatus.status;
            ReconStatusMessage = $reconStatus.message;
            ReconAttempt = $reconStatus.time;
        }
        [void]$ResultsCollection.Add($accountInfo)
    }
    $nextLink = $results.nextLink
}
function ConvertTo-UnixTime {
    param($seconds)
    $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    $ret = $origin.AddSeconds($seconds)
    $ret
}
function Get-AccountHistoryPasswordManagement {
    param($activity)
    $activityList = @("CPM Change Password Failed","CPM Reconcile Password Failed","CPM Change Password","CPM Reconcile Password","CPM Verify Password Failed","CPM Verify Password")
    $activity | Where-Object { $_.Activity -in $activityList} | Sort-Object -Property Time -Descending | Select-Object -First 1
}

function Get-SafesPSPAS {
    param($SafeName,[switch]$UseGen1)

    try {
        if($UseGen1){
            Get-PASSafe -UseGen1API -search $SafeName
        }else{
            Get-PASSafe -search $SafeName
        }
    }catch{
        LogError -message $Error[0]
    }

}
function Get-TimeSpanDays {
    param($datetimeValue)
    $creationDate=[DateTime]$datetimeValue
    $currentDate=Get-Date
    $currentDate2=[DateTime]$currentDate
    (New-TimeSpan -Start $creationDate -End $currentDate2).Days
}
function Get-LastVerifiedStatus{
    param($activity)
    #$data | Where Activity -like "CPM Verify Password*" | Sort-Object -Property Time -Descending | Select-Object -First 1

    $statusName = "Unknown"
    $time = $null
    $status = $activity | Where-Object { $_.Activity -like "CPM Verify Password*"} | Sort-Object -Property Time -Descending | Select-Object -First 1
    $message = ""
    if($null -ne $status){
        if($status.Activity -eq $CONST_Status_Verify) {$statusName = "Success"}
        if($status.Activity -eq $CONST_Status_VerifyFail) {
            $statusName = "Fail"
            $message = $status.Reason
            $time = $status.Time
        }
        
    }
    @{status=$statusName;message=$message;time=$time}
}
function Get-LastChangeStatus{
    param($activity)
    #$data | Where Activity -like "CPM Verify Password*" | Sort-Object -Property Time -Descending | Select-Object -First 1

    $statusName = "Unknown"
    $status = $activity | Where-Object { $_.Activity -like "CPM Change Password*"} | Sort-Object -Property Time -Descending | Select-Object -First 1
    $message = ""
    if($null -ne $status){
        if($status.Activity -eq $CONST_Status_Change) {$statusName = "Success"}
        if($status.Activity -eq $CONST_Status_ChangeFail) {
            $statusName = "Fail"
            $message = $status.Reason
            $time = $status.Time
        }
        
    }
    @{status=$statusName;message=$message;time=$time}
}
function Get-LastReconStatus{
    param($activity)
    #$data | Where Activity -like "CPM Verify Password*" | Sort-Object -Property Time -Descending | Select-Object -First 1

    $statusName = "Unknown"
    $status = $activity | Where-Object { $_.Activity -like "CPM Reconcile Password*"} | Sort-Object -Property Time -Descending | Select-Object -First 1
    $message = ""
    if($null -ne $status){
        if($status.Activity -eq $CONST_Status_Recon) {$statusName = "Success"}
        if($status.Activity -eq $CONST_Status_ReconFail) {
            $statusName = "Fail"
            $message = $status.Reason
            $time = $status.Time
        }
        
    }
    @{status=$statusName;message=$message;time=$time}
}
$CONST_Status_Verify        = "CPM Verify Password"
$CONST_Status_VerifyFail    = "CPM Verify Password Failed"
$CONST_Status_Change        = "CPM Change Password"
$CONST_Status_ChangeFail    = "CPM Change Password Failed"
$CONST_Status_Recon         = "CPM Reconcile Password"
$CONST_Status_ReconFail     = "CPM Reconcile Password Failed"
$Executing                  = $MyInvocation.MyCommand.Name
$currentUser                = $env:UserName
LogMessage -message "********* Executing $Executing ***********"
try {
    $configContent = Get-Content -Path $ConfigPath | ConvertFrom-Json
    $config = $configContent.GetAccountsPSPAS
    $VaultConfig = $configContent.VaultAuthorization
    LogMessage -message "Config file loaded '$ConfigPath'"
} catch {
    LogError -message $Error[0]
    return
}
if($configContent.DisableSSLVerify -eq "Yes"){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}
[pscredential]$cred = Get-ConnectCredential -config $VaultConfig -reason "Executing $Executing as user $currentUser"
if($null -eq $cred){
    LogError -message "Could not get app credential. Aborting."
    return
}
$AuthZHeader = $null
$PVWAURL = $config.RESTAPI.BaseURL
LogMessage -message "PVWAURL provided by config '$PVWAURL'"   
$TargetSafes = $config.Safes
LogMessage -message "Target safe override provided."
$SafeListReference = $config.SafeListReference
if($null -eq $SafeListReference -or $SafeListReference.Length -eq 0){
    LogMessage -message "No Safe List reference override provided NOR configured. Aborting."
    return
}
$TargetSafes | Foreach-Object {
    $SafeName               = $null
    $UseGen1PSPAS           = $_.UseGen1Api -eq "Yes"
    $sourcepath             = $null
    $ForceReportCreation    = $null
    $SafeName               = $_.TargetSafe
    $sourcepath             = $_.sourcepath
    $ForceReportCreation    = $_.ForceReportCreation
    $ResultsCollection      = [System.Collections.ArrayList]@()
    $IgnoreSafes            = $_.IgnoreSafes
    $FilterSafes            = $_.FilterSafes
    $ReportSafe             = $_.Reports_Safe
    $ReportFolder           = $_.Reports_Folder
    $filters                = Get-FilterExpression -filters $_.filters
    $filterexpression       = $null
    if(($filters | Measure-Object).Count -gt 0){
        $filterexpressions = $filters -join ' -and '
        $filterexpression = [scriptblock]::Create($filterexpressions)
    }
    $GetSafesListURI = $PVWAURL+'/PasswordVault/api/safes?search={0}&limit=100000'
    $GetSafesListURI = $GetSafesListURI -f $SafeName
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

    if($null -ne $FilterSafes -and $FilterSafes -ne ""){
        $safeFilterExp  = Create-FilterExpression -filters $FilterSafes
        $SafesList      = $SafesList | Where $safeFilterExp
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
    $NumberOfSafes = ($SafesList | Measure-Object).Count
    if($NumberOfSafes -eq 0){
        LogMessage -message "No safes were found matching '$SafeName'"
    }
    if($NumberOfSafes -gt 0){
        $SafesList | Select safeName | ForEach-Object {
            $RecordsFound = 0
            $ResultsCollection      = [System.Collections.ArrayList]@()
            $TargetSafeName = $_.safeName
            LogMessage -message "Generating report for safe '$TargetSafeName'."
            $GetAccountsURI = $PVWAURL+'/api/Accounts?filter=safeName eq {0}&offset=1&limit=1'
            $GetAccountsURI = $GetAccountsURI -f $TargetSafeName
            Enumerate-Results -AuthZHeader $AuthZHeader -TargetSafe $TargetSafeName -offset 0 -limit 1000
            $ResultsCollection | ForEach-Object {
                $Accounts = $_
                $ReportColumns = [System.Collections.ArrayList]@()
                [void]$ReportColumns.Add(@{Name="ID";expression={$_.Info.id}})
                [void]$ReportColumns.Add(@{Name="Target User Name";expression={$_.Info.userName}})
                [void]$ReportColumns.Add(@{Name="Target Address";expression={$_.Info.address}})
                [void]$ReportColumns.Add(@{Name="Safe Name";expression={$_.Info.safeName}})
                [void]$ReportColumns.Add(@{Name="Platform ID";expression={$_.Info.platformId}})
                [void]$ReportColumns.Add(@{Name="Last Changed";expression={ConvertTo-UnixTime $_.Info.secretManagement.lastModifiedTime}})
                [void]$ReportColumns.Add(@{Name="Management Status";expression={$_.Info.secretManagement.status}})
                [void]$ReportColumns.Add(@{Name="Management User";expression={$_.ManageUser}})
                [void]$ReportColumns.Add(@{Name="Last Verify Status";expression={$_.VerifyStatus}})
                [void]$ReportColumns.Add(@{Name="Last Verify Message";expression={$_.VerifyStatusMessage}})
                [void]$ReportColumns.Add(@{Name="Last Verify Attempt";expression={$_.VerifyAttempt}})
                [void]$ReportColumns.Add(@{Name="Last Change Status";expression={$_.ChangeStatus}})
                [void]$ReportColumns.Add(@{Name="Last Change Message";expression={$_.ChangeStatusMessage}})
                [void]$ReportColumns.Add(@{Name="Last Change Attempt";expression={$_.ChangeAttempt}})
                [void]$ReportColumns.Add(@{Name="Last Reconcile Status";expression={$_.ReconStatus}})
                [void]$ReportColumns.Add(@{Name="Last Reconcile Message";expression={$_.ReconStatusMessage}})
                [void]$ReportColumns.Add(@{Name="Last Reconcile Attempt";expression={$_.ReconAttempt}})
                $FileExists = Test-Path $sourcepath
                $AccountData = $Accounts | Select -Property $ReportColumns
                if($null -ne $filterexpression){
                    $AccountsReport = $AccountData | Where-Object $filterexpression
                }else{
                    $AccountsReport = $AccountData
                }
                $AccountsFound = ($AccountsReport | Measure-Object).Count
                $RecordsFound = $RecordsFound + $AccountsFound
                if($AccountsFound -gt 0){
                    if($FileExists){
                        $AccountsReport | Export-CSV $sourcepath -Append -NoTypeInformation
                    }else{
                        $AccountsReport | Export-CSV $sourcepath -NoTypeInformation
                    }
                }
            }
            LogMessage -message "$RecordsFound records found matching criteria for safe '$TargetSafeName'"
        }
    }
    Close-PASSession
    $filetoUpload = $sourcepath
    $filetoUploadExists = $false
    if($null -ne $filetoUpload -and $filetoUpload -ne ""){
        $filetoUploadExists = Test-Path $filetoUpload
    }
    if($filetoUploadExists){
        LogMessage -message "File '$filetoUpload' created."
        if($null -ne $ReportSafe -and $ReportSafe -ne ""){
            #Move file to safe
            LogMessage -message "Moving file '$filetoUpload' to vault"
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