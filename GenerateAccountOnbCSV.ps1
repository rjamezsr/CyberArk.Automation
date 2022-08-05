#region About GenerateAccountOnbCSV.ps1
###########################################################################
# This script pulls reads the pending accounts report and prepares a 
# CSV file that can be used for the Account_Onboarding_Untility script
#endregion
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid config file path")]
	[String]$ConfigPath="SampleOnboardingConfig.json",
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
    
)


. '.\Common.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"


#$ConfigData = Get-Content -Path $ConfigPath
#$ConfigDataJSON = $ConfigData | ConvertFrom-Json 
$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$ConfigDataJSON = (LoadJSONConfig -configpath $ConfigPath).GenerateOnboardingFile

$items = $ConfigDataJSON.Files | Where-Object {$_.Enabled -eq "true"}
$RegularExpressionFileFolder = $ConfigDataJSON.RegularExpressionFileFolder


if($null -ne $Filter){
    $ItemsFull = $ConfigDataJSON.Files | Where-Object -FilterScript $Filter
    $Items = $ItemsFull | Where-Object {$_.Enabled -eq "true"}
}




$items | Foreach-Object {
    $ReportFiles = $null
    $ReportFiles = [System.Collections.ArrayList]@()




    $item = $_
    
    $ReportSafe = $item.Reports_Safe
    $ReportFolder = $item.Reports_Folder
    
    #$OutputPath = $item.outputfilename
    $incrementFileCreate = $false
    $KeepSafeName = $item.KeepSafeName -eq "Yes"
    $KeepPlatformId = $item.KeepPlatformId -eq "Yes"
    if($null -ne $item.IncrementalFileBuild){
        $incrementFileCreate = $item.IncrementalFileBuild -eq "Yes"
    }
    if($incrementFileCreate){
        $OutputPath = GetFileName -Filepath $item.outputfilename -ReturnFullpath -NewFileName    
    }else{
        $OutputPath = $item.outputfilename
        if(Test-Path -Path $OutputPath){
            Remove-Item $OutputPath
        }
    }
    $OutputPath = GetFileName -Filepath $item.outputfilename -ReturnFullpath -NewFileName
    LogMessage -message "Generating onboarding file '$OutputPath'"
    Show_Progress -message "Generating onboarding file '$OutputPath'"

    $TargetSafeName = $item.targetsafe
    $TargetPlatformId = $item.targetplatformid
    $InputPath = $item.sourcepath
    if($null -ne $InputPath -and $InputPath -ne ""){
        if(Test-Path -Path $InputPath){
        }else{
            LogMessage -message "Source file '' does not exist!"
            return
        }
    }else {
        LogMessage -message "sourcepath was not set!"
        return
    }
    $CMDB_SourcePath = $item.CMDB_SourcePath
    $SourceFileExists = $false
    if($null -ne $CMDB_SourcePath -and $CMDB_SourcePath -ne ""){
        $SourceFileExists = Test-Path -Path $CMDB_SourcePath
    }
    if($SourceFileExists){
        $outputcolumns = $item.outputcolumns
        $defaultpwd = $item.defaultpwd
        $filtervalues = [System.Collections.ArrayList]@()
        $columns = [System.Collections.ArrayList]@()
        $filtersValid = $true
        $item.filters | Foreach-Object {
            # if($_.operation -eq "in"){
            #     [void]$filtervalues.Add([scriptblock]::Create('$_.' + $_.column + ' -' + $_.operation + ' ("' + $_.value + '") -split ","'))    
            # }else{
            #     [void]$filtervalues.Add([scriptblock]::Create('$_.' + $_.column + ' -' + $_.operation + ' "' + $_.value + '"'))
            # }

            $filterItem = $_
            switch ($_.operation) {
                "in"  {
                    [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' ("' + $filterItem.value + '" -split ",")'))
                    break
                }
                "match" {
                    
                    if($null -ne $RegularExpressionFileFolder -and $RegularExpressionFileFolder -ne ""){
                        $matchTo = ""
                        $RegExFilePath = Join-Path -Path $RegularExpressionFileFolder -ChildPath $filterItem.value
                        if(Test-Path $RegExFilePath){
                            $matchTo = Get-Content $RegExFilePath
                            if($null -ne $matchTo -and $matchTo -ne ""){
                                [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $matchTo + '"'))        
                            }else{
                                $filtersValid = $false
                            }
                        }else{
                            $filtersValid = $false
                        }
                    }else{
                        $filtersValid = $false
                    }
                    
                    
                    break
                }
                "notmatch" {
                    $matchTo = ""
                    $RegExFilePath = Join-Path -Path $RegularExpressionFileFolder -ChildPath $filterItem.value
                    if(Test-Path $RegExFilePath){
                        $matchTo = Get-Content $RegExFilePath
                        if($null -ne $matchTo -and $matchTo -ne ""){
                            [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $matchTo + '"'))        
                        }else{
                            $filtersValid = $false
                        }
                    }else{
                        $filtersValid = $false
                    }
                    
                    break
                }
                default {
                    [void]$filtervalues.Add([scriptblock]::Create('$_.' + $filterItem.column + ' -' + $filterItem.operation + ' "' + $filterItem.value + '"'))
                    break
                }
            }
        }
        if($filtersValid){
        }else{
            LogMessage -message "Filters were invalid. Aborting."
            return
        }
        $CMDB_SourceKey = $item.CMDB_SourceKey
        $CMDB_TargetKey = $item.CMDB_TargetKey
        $CMDB_Output = $item.CMDB_Output
        $CMDB_Output_Alias = $item.CMDB_Output_Alias
        $CMDB_match = $item.CMDB_match # default is Yes
        $filterexpressions = $filtervalues -join ' -and '
        $filterexpression = [scriptblock]::Create($filterexpressions)
        $data = Import-Csv -Path $InputPath
        $CMDB = Import-Csv -Path $CMDB_SourcePath


        

        #$NumOfPendingAccounts = $data.Length
        $NumOfPendingAccounts = ($data | Measure-Object).Count
        #$NumOfServers = $CMDB.Length
        $NumOfServers = ($CMDB | Measure-Object).Count

        LogMessage -message "$NumOfPendingAccounts = number of total pending accounts"
        LogMessage -message "$NumOfServers = number of total servers"

        $CMDB_MatchExpression = [scriptblock]::Create('$_.' + $CMDB_Output_Alias + ' -ne $null')
        $NumOfRecordsGenerated = 0

        $queryresult = $data | Where-Object $filterexpression | 
            Select-Object -Property @{Name="Username";expression={$_.Username}}, 
                #@{Name='safe';Expression={$TargetSafeName}} ,
                @{Name='safe';Expression={if($KeepSafeName){$_.safe}else{$TargetSafeName}}} ,
                #@{Name='safename';Expression={$TargetSafeName}} ,
                @{Name='safename';Expression={if($KeepSafeName){$_.safename}else{$TargetSafeName}}} ,
                #@{Name="platformid";expression={$TargetPlatformId}}, 
                @{Name='platformid';Expression={if($KeepPlatformId){$_.platformid}else{$TargetPlatformId}}} ,
                @{Name="password";expression={$defaultpwd}}, 
                @{Name="PublicSSHKeyPath";expression={$_.Path}}, 
                #The field below is pulled from the CMDB CSV file. 
                #@{Name="CMDB";expression={ ($CMDB | Where-Object $CMDB_SourceKey -eq $_.$CMDB_TargetKey | Select $CMDB_Output -first 1).$CMDB_Output }},
                @{Name=$CMDB_Output_Alias;expression={ ($CMDB | Where-Object $CMDB_SourceKey -eq $_.$CMDB_TargetKey | Select $CMDB_Output -first 1).$CMDB_Output }},
                @{Name="Filename";expression={$_.Filename}},
                @{Name="Name";expression={$_.Name}},
                @{Name="address";expression={$_.Address}},
                @{Name="EnableAutoMgmt";expression={$_.EnableAutoMgmt}}, 
                @{Name="ManualMgmtReason";expression={$_.ManualMgmtReason}}, 
                @{Name="RemoteMachineAddresses";expression={$_.RemoteMachineAddresses}}, 
                @{Name="RestrictMachineAccessToList";expression={$_.RestrictMachineAccessToList}},
                @{Name="GroupName";expression={$_.GroupName}}, 
                @{Name="GroupPlatformID";expression={$_.GroupPlatformID}}, 
                @{Name="database";expression={$_.database}}, 
                @{Name="dsn";expression={$_.dsn}}, 
                @{Name="port";expression={$_.port}}, 
                @{Name="Comment";expression={$_.Comment}},
                @{Name="Encryption";expression={$_.Encryption}},
                @{Name="AccountCategory";expression={$_.AccountCategory}},
                @{Name="AccountDiscoveryDate";expression={$_.AccountDiscoveryDate}},
                @{Name="AccountEnabled";expression={$_.AccountEnabled}},
                @{Name="AccountExpirationDate";expression={$_.AccountExpirationDate}},
                @{Name="AccountOSGroups";expression={$_.AccountOSGroups}},
                @{Name="AccountType";expression={$_.AccountType}},
                @{Name="CreationMethod";expression={$_.CreationMethod}},
                @{Name="Dependencies";expression={$_.Dependencies}},
                @{Name="DeviceType";expression={$_.DeviceType}},
                @{Name="DiscoveryPlatformType";expression={$_.DiscoveryPlatformType}},
                @{Name="Domain";expression={$_.Domain}},
                @{Name="Fingerprint";expression={$_.Fingerprint}},
                @{Name="Folder";expression={$_.Folder}},
                @{Name="Format";expression={$_.Format}},
                @{Name="GID";expression={$_.GID}},
                @{Name="LastLogonDate";expression={$_.LastLogonDate}},
                @{Name="LastPasswordSetDate";expression={$_.LastPasswordSetDate}},
                @{Name="Length";expression={$_.Length}},
                @{Name="MachineOSFamily";expression={$_.MachineOSFamily}},
                @{Name="OSVersion";expression={$_.OSVersion}},
                @{Name="OU";expression={$_.OU}},
                @{Name="PasswordNeverExpires";expression={$_.PasswordNeverExpires}},
                @{Name="Path";expression={$_.Path}},
                @{Name="SID";expression={$_.SID}},
                @{Name="UID";expression={$_.UID}},
                @{Name="SSHKey";expression={"no key"}},
                @{Name="UserDisplayName";expression={$_.UserDisplayName}},
                @{Name="id";expression={$_.id}}
        

        #$NumOfInitialAccountsPulled = $queryresult.Length
        $NumOfInitialAccountsPulled = ($queryresult | Measure-Object).Count
        

        LogMessage -message "$NumOfInitialAccountsPulled = initial records found"
        $outputcolumns = $outputcolumns -split ","

        $outputcolumns | ForEach-Object {
            [void]$columns.Add(@{Name = "$_"; expression="$_"})
        }
        if($CMDB_match -eq "No"){
            $queryresult | Select-Object -Property $columns | Export-Csv -Path $OutputPath -NoTypeInformation
            #$NumOfRecordsGenerated = $queryresult.Length
            $NumOfRecordsGenerated = ($queryresult | Measure-Object).Count
            
            
        }else{
            #$queryresult | Where CMDB -ne $null | Select-Object -Property $columns | Export-Csv -Path $OutputPath -NoTypeInformation
            $report = $queryresult |  Where-Object $CMDB_MatchExpression | Select-Object -Property $columns #| Export-Csv -Path $OutputPath -NoTypeInformation
            $report | Export-Csv -Path $OutputPath -NoTypeInformation
            #$NumOfRecordsGenerated = $report.Length
            $NumOfRecordsGenerated = ($report | Measure-Object).Count

        }
        Show_Progress -message "$NumOfRecordsGenerated Records generated"
        LogMessage -message "***********************************************************"
        LogMessage -message "***********************************************************"
        LogMessage -message "$NumOfRecordsGenerated = records written to file SAFE: $TargetSafeName"
        LogMessage -message "***********************************************************"
        LogMessage -message "***********************************************************"
        $OutputFileExists = Test-Path -Path $OutputPath
        if($OutputFileExists -and $NumOfRecordsGenerated -gt 0){
            $ReportFiles.Add($OutputPath)
        }

    }else{
        LogMessage -message "CMDB Source file '$CMDB_SourcePath' does not exist"
    }
    if($ReportFiles.Count -gt 0){
        if($null -ne $ReportSafe -and $ReportSafe -ne "" -and $null -ne $ReportFolder -and $ReportFolder -ne ""){

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

            $ReportFiles | Foreach-Object {
                $filetoUpload = $_
                $progressMoveFile = Show_Progress -progressObject $progressMoveFile -list $ReportFiles -message "Uploading file $filetoUpload"
                #$ReportSafe = $_.Safe
                #$ReportFolder = $_.Folder
                LogMessage -message "File '$filetoUpload' created. Now moving file to vault"
                PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                    -Usr $appUsr `
                    -password $PwdC -AsSecureString `
                    -VaultAddress $VaultConfig.vaultip `
                    -sessionid $VaultConfig.sessionid `
                    -PACLI_EXE $VaultConfig.pacliexe `
                    -TargetFolder $ReportFolder `
                    -TargetSafe $ReportSafe `
                    -inputpath $filetoUpload

                Remove-Item $filetoUpload 
            }


        }
        
        
    } 
}
