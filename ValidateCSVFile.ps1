param (
    
    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid ValidateCSVFile config file path")]
	[String]$ConfigPath="Sample_ValidateCSVFile_Config.json"
    
)

. '.\Common.ps1'
. '.\Common.DataValidations.ps1'
. '.\Common.Mail.ps1'



$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"
$currentUser = $env:UserName

$VaultConfig = (LoadAccountsFeedConfig -configpath $ConfigPath).VaultAuthorization
$ValidateCSVFileConfig = (LoadAccountsFeedConfig -configpath $ConfigPath).ValidateCSVFile


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


$ValidateCSVFileConfig | ForEach-Object {
    $item = $_
    $validationName       = $item.Name
    
    $dataExists           = $false
    $configFileExists     = $false
    $ValidationConfigFile = $item.Validation.ValidationConfigFile
    
    $ValidationResultFile = $item.Validation.ValidationResultFile
    $ValidationResultSafe = $item.Validation.ValidationResultSafe
    $ValidationResultSafeFolder = $item.Validation.ValidationResultSafeFolder
    
    $ValidResultFile = $item.Validation.ValidResultFile
    $ValidResultSafe = $item.Validation.ValidResultSafe
    $ValidResultSafeFolder = $item.Validation.ValidResultSafeFolder
    
    $NotificationConfigFile = $item.Validation.NotificationConfig.ConfigPath
    $NotificationTemplateName = $item.Validation.NotificationConfig.TemplateName

    $DeleteSourceFile = $item.DeleteSourceFile -eq "Yes"

    $TargetValidFileSafe = $item.TargetSafe
    $TargetValidFileFolder = $item.TargetFolder

    $outputpath = $item.sourcepath

    if($null -eq $outputpath -or $outputpath -eq ""){
        LogMessage -message "Source file was not specificied in the config file"
        return
    }
    if(Test-Path -Path $outputpath){
    }else{
        LogMessage -message "Source file '$outputpath' does not exist"
        return
    }
    $progressValidateFile = Show_Progress -progressObject $progressValidateFile -list $progressValidateFile -message "Execute validation '$validationName' for file '$outputpath'"
    $isValid = $true
    $validateData = $outputpath | Import-Csv
    $dataExists = ($validateData | measure).Count -gt 0
    $configFileExists = $null -ne $ValidationConfigFile -and (Test-Path -Path $ValidationConfigFile)
    if($dataExists){
    }else{
        LogMessage -message "Source data file contains no data."
    }
    if($configFileExists){
    }else{
        LogMessage -message "Validation Config file is invalid or does not exist."
    }
    if($configFileExists -and $dataExists){
        LogMessage -message "Validating file '$outputpath'"
        $validationResult = Validate-QueryData -ConfigData $ValidationConfigFile -data $validateData
        $isValid = ($validationResult | Where IsValid -eq $false | measure).Count -eq 0
        if($null -ne $validationResult.ValidData -and ($validationResult.ValidData | Measure).Count -gt 0){
            if($null -ne $ValidResultFile -and $ValidResultFile -ne "" -and $null -ne $ValidResultSafe -and $ValidResultSafe -ne "" -and $null -ne $ValidResultSafeFolder -and $ValidResultSafeFolder -ne ""){
                if(Test-Path -Path $ValidResultFile){
                    Remove-Item -Path $ValidResultFile
                }
                $validationResult.ValidData | Export-Csv -Path $ValidResultFile -NoTypeInformation
                $countOfValidResults = ($validationResult.ValidData | Measure).Count
                LogMessage -message "$countOfValidResults valid results found. Results written to file '$ValidResultFile' created. Now moving file to vault"
                PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
                    -Usr $appUsr `
                    -password $PwdC -AsSecureString `
                    -VaultAddress $VaultConfig.vaultip `
                    -sessionid $VaultConfig.sessionid `
                    -PACLI_EXE $VaultConfig.pacliexe `
                    -TargetFolder $ValidResultSafeFolder `
                    -TargetSafe $ValidResultSafe `
                    -inputpath $ValidResultFile

                Remove-Item -Path $ValidResultFile
            }
        } 
        if($isValid -eq $false){
            Export-ValidationReport -Outputpath $ValidationResultFile -ValidationObject $validationResult
            LogMessage -message "(CYBERARK)File is INVALID. File is '$outputpath'"
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

                Remove-Item -Path $ValidationResultFile

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
        if($DeleteSourceFile){
            Remove-Item -Path $outputpath
        } 
    }
      
}