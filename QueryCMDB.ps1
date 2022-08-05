
#region About QueryUCMDB.ps1
###########################################################################
# This script pulls a report from UCMDB and outputs to CSV file
# 
<#

!!!!!   READ THIS BEFORE RUNNING THIS SCRIPT !!!!!!!!

This script uses 3 accounts:
    pacli app user
    pacli gw user
    CMDB api user

Flow:
1. The script uses the pacli gw user to login to the vault and retreive credentis of the pacli app user
2. Then, using the pacli app user, the script logs in to the vault to fetch the passwod of the CMPD api user account
3. Finally, using the CPMD api user account, the script exports CMDB data

To complete the flow described above, here are the required and recommended setup instructions

1. (required) Create the pacli gw user account in the vault. Also create a credential file. 
2. (required) Create a safe to store the pacli app user. Example PACLI Accounts
3. (required) Onboard the pacli app user account to the vault and in to the safe created above
4. Implement object level access control on the safe created
5. (required) Give only the pacli gw user account access to the password value (retirieve/list)
6. All other users, except the password manager, should not be permited to retrieve the password. 
7. (required) Onboard the CMDP account to a new Safe safe. For example, CMDB Accounts 
8. (required) Give the pacli app user, and only this user, permission to retrieve the password for the CMDB account
9. For the pacli app user, implement a OTP policy. 


#>
#endregion
param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid CMDB API config file path")]
	[String]$CMDBConfigPath="C:\\repo\\Azure.DevOps\\Prolab-IDM\\CyberArk.Automation.Config\\AccountOnboardingAutomation.json",
    [Parameter(Mandatory=$false)]
    [Switch]$DisableSSLVerify,
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
    
)

. '.\Common.ps1'
. '.\Common.DataValidations.ps1'
. '.\Common.Mail.ps1'


$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName
if($DisableSSLVerify){
    DisableSSL
}


$VaultConfig = (LoadAccountsFeedConfig -configpath $CMDBConfigPath).VaultAuthorization
$CMDBConfig = (LoadAccountsFeedConfig -configpath $CMDBConfigPath).CMDB
$Items = $CMDBConfig.Reports | Where-Object {$_.Enabled -eq "true"}

if($null -ne $Filter){
    $Items = $CMDBConfig.Reports | Where-Object -FilterScript $Filter
}


$Items | ForEach-Object {
    $item = $_
    Show_Progress -message ("Processing CMDB Query: '{0}'" -f $item.Name)
    $ItemName = $item.Name
    LogMessage -message "Processing item '$ItemName'"

    $StreamOutput = $_.StreamOutput -eq "Yes"
    $Stream = [System.Collections.ArrayList]@()


    $reportname = $item.reportname
    $filters = $item.filters
    $outputpath = $item.sourcepath
    $AuthZURI = $item.logonuri
    $QueryURI = $item.reporturi
    $GrantType = $item.grant_type
    $AuthZHeader = $null
    $Output = $null
    $LogonFile = $VaultConfig.logonfile

    $ValidationConfigFile = $item.Validation.ValidationConfigFile
    $ValidationResultFile = $item.Validation.ValidationResultFile
    $ValidationResultSafe = $item.Validation.ValidationResultSafe
    $ValidationResultSafeFolder = $item.Validation.ValidationResultSafeFolder
    $NotificationConfigFile = $item.Validation.NotificationConfig.ConfigPath
    $NotificationTemplateName = $item.Validation.NotificationConfig.TemplateName

    


    $outputpathFolder = Split-Path -parent $outputpath
    if(-not(Test-Path $outputpathFolder)){
        LogError -message "Output folder '$outputpathFolder' does not exist!"
        return
    }


    $LogonFileExists = Test-Path $LogonFile
    if($LogonFileExists -eq $false){
        LogError -message "Logon file does not exist. Logon file '$LogonFile'" 
        return
    }else{
        LogMessage -message "Logon file found $LogonFile"
    }


    $CSVColumnOutputHeader = $item.outputcolumns
    $OutputColumns = $item.outputcolumns.Split(",")
    $CSVFormatOutput = ""
    $ColumnCount = 0
    $OutputColumns | ForEach-Object {$CSVFormatOutput = $CSVFormatOutput + """{$ColumnCount}""" + ",";$ColumnCount = $ColumnCount + 1}
    if($ColumnCount -gt 0){$CSVFormatOutput = $CSVFormatOutput.Substring(0,$CSVFormatOutput.Length - 1)}

    #get app user cred
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
    }

    $appUsr = $VaultConfig.user.Trim()
    $AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
    $AppPwdC = $AppPwdC.Replace(" ","") 

    $PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force


    if($GrantType -ne "None"){
        




        $reportCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
            -user $appUsr `
            -password $PwdC -AsSecureString `
            -sessionid $VaultConfig.sessionid `
            -vaultip $VaultConfig.vaultip `
            -pacliexe $VaultConfig.pacliexe `
            -targetsafe $item.reportusersafe `
            -folder $item.reportuserfolder `
            -objectname $item.reportuserobjectname `
            -reason "Get server list from UCMDB host" 
            
        if($null -eq $reportCred) {
            LogError -message "Could not get report user credential!" 
            Throw "Could not get report user credential!"  
        }
            
        $Usr = $item.reportusername.Trim()
        $PwdCMDB = $reportCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
        $PwdCMDB = $PwdCMDB.Replace(" ","") 

        
    }


    $OutputFileExists = Test-Path $outputpath
    if($OutputFileExists){
        if($StreamOutput){
        }else{
            Remove-Item $outputpath
            New-Item -Path $outputpath 
        }
    }else{
        if($StreamOutput){
            LogMessage -message "Query CMDB configuration is set to stream, but the file '$outputpath' does not exist. The file must exist for stream to work. "
        }
    }

    
    if(($StreamOutput -and $OutputFileExists) -or $StreamOutput -eq $false){
        if($item.outputheaders -eq "Yes"){$CSVColumnOutputHeader | Out-File $outputpath}

        Write-Verbose -Message "Grant Type is: $GrantType"

        $queryresult = $null
        switch ($GrantType) {
            "None" {  
                $queryresult = Invoke-RestMethod -Uri $QueryURI -Method Get -ContentType "application/json"
                break
            }
            "Basic" {  
                $token = REST_Logon -Usr $Usr -PwdC $PwdCMDB -AuthZURI $AuthZURI -AuthZGrantType $GrantType
                $AuthZHeader = @{
                    'Authorization' = $token
                }
                $queryresult = Invoke-RestMethod -Uri $QueryURI -Method Post -Body $reportname -Headers $AuthZHeader -ContentType "application/json"
                break
            }
            "Bearer" {  
                $token = REST_Logon -Usr $Usr -PwdC $PwdCMDB -AuthZURI $AuthZURI -AuthZGrantType $GrantType
                $AuthZHeader = @{
                    'Authorization' = $token
                }
                $queryresult = Invoke-RestMethod -Uri $QueryURI -Method Get -Headers $AuthZHeader -ContentType "application/json"
                break
            }
            "Basic Web" {
                $password = ConvertTo-SecureString $PwdCMDB -AsPlainText -Force
                $Cred = New-Object System.Management.Automation.PSCredential ($Usr, $password)  
                $queryresult = Invoke-RestMethod -Uri $QueryURI -Credential $Cred -ContentType "application/json"
                break
            }
            Default {
                $Msg = "Grant type is not specified or invalid"
                LogMessage -message $Msg
                Throw $Msg
                return
                break
            }
        }
        if($null -eq $queryresult){
            $Msg = "Nothing returned from API call"
            LogMessage -msg $Msg
            Throw $Msg
            return
        }
        try {
            $arr = $null
            if(($null -eq $item.path_data -and $null -eq $item.path_data_properties) -or ($item.path_data -eq "" -and $item.path_data_properties -eq "")){
                $arr = $queryresult | ConvertTo-Json
            }else{
                $reportcontainer = $item.path_data
                $reportpropertiescontainer = $item.path_data_properties
                $arr = $queryresult.$reportcontainer | ConvertTo-Json
            }
        
        
        
            #$reportarr = $arr | ConvertFrom-Json | Select-Object -Expand $_ # | Format-Table
            $reportarr = $arr | ConvertFrom-Json #| Select-Object -Expand $_ # | Format-Table

            if($null  -eq $arr.Count -or $arr.Count -eq 0){
                LogMessage -message "No data returned with given path_data and path_data_properties"
            }
            $reportarr | ForEach-Object {
                $progress = Show_Progress -progressObject $progress -list $reportarr
                $innerarr =  $_.$reportpropertiescontainer 
                if($null  -eq $innerarr){
                    $innerarr =  $_
                    if($null  -eq $innerarr){
                        LogMessage -message "No data returned with given path_data and path_data_properties"
                    }
                }
                $WriteData = $true
                $filters | ForEach-Object {
                    $column     = $_.column
                    $operation  = $_.operation
                    $value      = $_.value
                    $result     = $_.result
                    $opresult = $false
                    $attribute_value = ($innerarr | Select-Object $column).$column
                    $attribute_condition_result = $null
                    switch ($operation) {
                        "null"  {
                            $attribute_condition_result = $attribute_value -eq $null;
                            $opresult =  ($attribute_condition_result -eq $true -and $result -eq "true") -or `
                                ($attribute_condition_result -eq $false -and $result -eq "false");
                            break
                        }
                        "eq"  {
                            $attribute_condition_result = $attribute_value -eq $value;
                            $opresult =  ($attribute_condition_result -eq $true -and $result -eq "true") -or `
                                ($attribute_condition_result -eq $false -and $result -eq "false");
                            break
                        }
                        "like"   {
                            $attribute_condition_result = $attribute_value -like $value;
                            $opresult =  ($attribute_condition_result -eq $true -and $result -eq "true") -or `
                                ($attribute_condition_result -eq $false -and $result -eq "false"); 
                            break
                        }
                        "in" {
                            $list = -split $value
                            $attribute_condition_result = $attribute_value -in $list;
                            $opresult =  ($attribute_condition_result -eq $true -and $result -eq "true") -or `
                                ($attribute_condition_result -eq $false -and $result -eq "false"); 
                            break
                        }
                        "in-like" {
                            $list = -split $value
                            $attribute_condition_result = $false
                            $list | ForEach-Object {
                                if($attribute_value -like  $_){
                                    $attribute_condition_result = $true
                                }
                            }
                            $opresult =  ($attribute_condition_result -eq $true -and $result -eq "true") -or `
                                ($attribute_condition_result -eq $false -and $result -eq "false"); 
                            break
                        }
                        default {$opresult = $false; break}
                        }
                        if($opresult -eq $false) {$WriteData = $false}
                }
                if($WriteData -eq $true){
                    $output = ""
                    $OutputColumns | ForEach-Object {
                        $attribute_value = ""
                        $attribute = $_
                        if($attribute -ne $null -and $attribute -ne "") {$attribute_value = ($innerarr | Select-Object $attribute).$attribute}
                        if($attribute_value -eq $null) {$attribute_value = ""}
                        if($item.enclose_values -eq "Yes")
                        {
                            $attribute_value = """" + $attribute_value.ToString()  + ""","
                        }else{
                            $attribute_value = $attribute_value.ToString()  + ","
                        }

                        $output = $output + $attribute_value
                    }
                    if($output.Length -gt 0){
                        $output = $output.SubString(0,$output.Length - 1)
                        if($StreamOutput){
                            $Stream.Add($output)
                        }else{
                            $output | Out-file -FilePath $outputpath -Append
                        }

                    }
                }
            } # end foreach
            if($StreamOutput){
                Set-Content -Path $outputpath -Value ($Stream)
            }

            $isValid = $true
            if($null -ne $ValidationConfigFile -and (Test-Path -Path $ValidationConfigFile)){
                $validateData = $outputpath | Import-Csv
                $validationResult = Validate-QueryData -ConfigData $ValidationConfigFile -data $validateData
                $isValid = ($validationResult | measure).Count -eq 0
                if($isValid -eq $false){
                    Export-ValidationReport -Outputpath $ValidationResultFile -ValidationObject $validationResult
                    LogMessage -message "CMDB File was invalid."
                    if($null -ne $ValidationResultSafe -and $ValidationResultSafe.Length -ne 0){
                        LogMessage -message "Validation result file created. Now moving file to vault"
                        PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                            -Usr $appUsr `
                            -password $PwdC -AsSecureString `
                            -VaultAddress $VaultConfig.vaultip `
                            -sessionid $VaultConfig.sessionid `
                            -PACLI_EXE $VaultConfig.pacliexe `
                            -TargetFolder $ValidationResultSafeFolder `
                            -TargetSafe $ValidationResultSafe `
                            -inputpath $ValidationResultFile
                        if($null -ne $NotificationConfigFile -and (Test-Path -Path $NotificationConfigFile) -and $NotificationTemplateName -ne ""){
                            $NotificationTemplate = (Get-Content $NotificationConfigFile | ConvertFrom-Json).Templates | Where Name -eq $NotificationTemplateName
                            $SubjectParams = @($item.Name)
                            $BodyParams = @($item.name,$validationResult.Data.Description)
                            $messageSent = Send-Message -ConfigPath $NotificationConfigFile -template $NotificationTemplate -SubjectParams $SubjectParams -BodyParams $BodyParams
                            if($messageSent -eq $false){
                                LogMessage -message "Could not send notification."
                            }
                        }
                    
                    }
                }
            }

            if($null -ne $item.CMDB_file_safe -and $item.CMDB_file_safe.Length -ne 0 -and $isValid){
                #Move file to safe
                LogMessage -message "File created. Now moving file to vault"
                $uploadPath = (Get-ChildItem -Path $outputpath).FullName
                PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                    -Usr $appUsr `
                    -password $PwdC -AsSecureString `
                    -VaultAddress $VaultConfig.vaultip `
                    -sessionid $VaultConfig.sessionid `
                    -PACLI_EXE $VaultConfig.pacliexe `
                    -TargetFolder $item.CMDB_file_folder `
                    -TargetSafe $item.CMDB_file_safe `
                    -inputpath $uploadPath
            }
        

        }
        catch [System.Net.WebException],[System.IO.IOException],[System.SystemException] {
            LogError -message $Error[0]
            Throw $Error[0] 
        }
    }

    
    
}