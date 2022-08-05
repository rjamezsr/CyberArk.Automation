#region About GetPendingAccounts.ps1
###########################################################################
# This script reads account object data from the target safe and stores it in a CSV file
#
#endregion
param (

    [Parameter(Mandatory=$false,HelpMessage="Please enter a valid Config file path")]
	[String]$ConfigPath="Sample_GetAccounts_Config.json",
    [Parameter(Mandatory=$false)]
    [ScriptBlock]$Filter=$null 
    
)


. '.\Common.ps1'

$Executing = $MyInvocation.MyCommand.Name
LogMessage -message "********* Executing $Executing ***********"

$VaultConfig = (LoadJSONConfig -configpath $ConfigPath).VaultAuthorization
$config = (LoadJSONConfig -configpath $ConfigPath).GetAccounts
$safes = $config.Safes


if($null -ne $Filter){
    $safes = $config.Safes | Where-Object -FilterScript $Filter
}


$safes | ForEach-Object {
    $item = $_ 
    $ItemName = $item.TargetSafe
    LogMessage -message "Getting accounts for safe '$ItemName'"

    $SafeName = $item.TargetSafe
    $Folder = "root"
    $OutputHeader = "UserName,Address,AccountDiscoveryDate,AccountEnabled,AccountOSGroups,DiscoveryPlatformType,LastPasswordSetDate,LastLogonDate,PasswordNeverExpires,AccountExpirationDate,OSVersion,AccountCategory,MachineOSFamily,AccountType,CreationMethod,Dependencies,Domain,UserDisplayName,OU,SID,UID,GID,Fingerprint,Length,Path,Format,Comment,Encryption,DeviceType,Safe,Folder,Filename,TargetSafeName,TargetPlatformId,Name,ExtraPass3Name"
    $OutputFormat = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}","{11}","{12}","{13}","{14}","{15}","{16}","{17}","{18}","{19}","{20}","{21}","{22}","{23}","{24}","{25}","{26}","{27}","{28}","{29}","{30}","{31}","{32}","{33}","{34}","{35}"'
    $OutputDelimiter = ","

    $outputpath  = $item.sourcepath

    $PullData = $true

    $OutputFileExists = Test-Path $outputpath
    if($OutputFileExists -and $item.ForceReportCreation -eq "Yes"){
        
        Remove-Item $outputpath 
    }else{
        if($OutputFileExists -and $item.ForceReportCreation -ne "Yes"){
            $PullData = $false
        }
    }




    $OutputHeader | Out-file -FilePath $outputpath


    $appUserCred = PoSHPACLI_GetPassword -vaultname $VaultConfig.vaultname `
        -user $VaultConfig.gwuser `
        -logonfile $VaultConfig.logonfile `
        -sessionid $VaultConfig.sessionid `
        -vaultip $VaultConfig.vaultip `
        -pacliexe $VaultConfig.pacliexe `
        -targetsafe $VaultConfig.gwusersafe `
        -folder $VaultConfig.gwuserfolder `
        -objectname $VaultConfig.gwuserobjectname `
        -reason "Get app account for Pending Accounts Report" -autoChangePassword $true




    if($null -eq $appUserCred) {
        LogError -message "Could not get report app user credential!" 
        Throw "Could not get report app user credential!"  
    }

    $appUsr = $VaultConfig.user.Trim()
    $AppPwdC = $appUserCred.Password[1] # Not sure why this comes back as array and not string. Maybe b/c in my lab, account is not on platform policy 
    $AppPwdC = $AppPwdC.Replace(" ","") 

    $PwdC = ConvertTo-SecureString $AppPwdC -AsPlainText -Force




    if($PullData){


        PoSHPACLI_ConnectVault -VaultName $VaultConfig.vaultname `
            -Username $appUsr `
            -password $PwdC -AsSecureString `
            -address $VaultConfig.vaultip `
            -sessionid $VaultConfig.sessionid `
            -pacliexe $VaultConfig.pacliexe

        $RowNum = 0



        #$safe = Open-PVSafe -safe $SafeName
        $filelistreport = PoSHPACLI_GetFileListReport -SafeName $item.TargetSafe -Folder $item.TargetFolder
        if($filelistreport -eq $null) {
            LogMessage -message "File list is empty"
        }
        $filelist = $filelistreport | Where-Object {$_.Filename -ne ""} | Group-Object -Property Filename | Select-Object -Property @{Name='Filename';Expression={$_.Name}}


        $CountOfRows = $filelist.Count
        $filelist | Foreach-Object {
            $FileName = $_.FileName
            $Name = $Filename
            if($FileName -eq $null -or $FileName -eq ""){
                LogMessage -message "Filename is null"
            }else{
                $Ext = $FileName.substring($FileName.length-4,4).ToUpper()
                $RowNum = $RowNum + 1

                $UserName = ""
                $Address = ""
                $AccountDiscoveryDate = ""
                $AccountEnabled = ""
                $AccountOSGroups = ""
                $DiscoveryPlatformType = ""
                $LastPasswordSetDate = ""
                $LastLogonDate = ""
                $PasswordNeverExpires = ""
                $AccountExpirationDate = ""
                $OSVersion = ""
                $AccountCategory = ""
                $MachineOSFamily = ""
                $AccountType = ""
                $CreationMethod = ""
                $Dependencies = ""
                $DeviceType = ""

                $Domain = ""
                $UserDisplayName = ""
                $OU = ""
                $SID = ""


                $UID = ""
                $GID = ""

                $Fingerprint = ""
                $Length = ""
                $Path = ""
                $Format = ""
                $Comment = ""
                $Encryption = ""



                if($Ext -ne ".TXT"){

                    #Open-PVSafe $TargetSafeName

                    #$FC_All = Get-PVFileCategory -file $FileName -safe $SafeName -folder $Folder
                    $FC_All = PoSHPACLI_GetFileCategory -FileName $FileName -SafeName $item.TargetSafe -Folder $item.TargetFolder
                
                    $UserName = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UserName" -FileCategoryObject $FC_All
                    $Address = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Address" -FileCategoryObject $FC_All
                    $AccountDiscoveryDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountDiscoveryDate" -FileCategoryObject $FC_All
                    $AccountEnabled = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountEnabled" -FileCategoryObject $FC_All
                    $AccountEnabled = PoSHPACLI_GetFileCategoryValue -FileCategoryName $AccountEnabled.ToLower()
                    $AccountOSGroups = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountOSGroups" -FileCategoryObject $FC_All
                    $DiscoveryPlatformType = PoSHPACLI_GetFileCategoryValue -FileCategoryName "DiscoveryPlatformType" -FileCategoryObject $FC_All
                    $LastPasswordSetDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "LastPasswordSetDate" -FileCategoryObject $FC_All
                    $LastLogonDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "LastLogonDate" -FileCategoryObject $FC_All
                    $PasswordNeverExpires = PoSHPACLI_GetFileCategoryValue -FileCategoryName "PasswordNeverExpires" -FileCategoryObject $FC_All
                    $PasswordNeverExpires = PoSHPACLI_GetFileCategoryValue -FileCategoryName $PasswordNeverExpires.ToLower()
                    $AccountExpirationDate = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountExpirationDate" -FileCategoryObject $FC_All
                    $OSVersion = PoSHPACLI_GetFileCategoryValue -FileCategoryName "OSVersion" -FileCategoryObject $FC_All
                    $AccountCategory = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountCategory" -FileCategoryObject $FC_All
                    $AccountCategory = PoSHPACLI_GetFileCategoryValue -FileCategoryName $AccountCategory.ToLower()
                    $MachineOSFamily = PoSHPACLI_GetFileCategoryValue -FileCategoryName "MachineOSFamily" -FileCategoryObject $FC_All
                    $AccountType = PoSHPACLI_GetFileCategoryValue -FileCategoryName "AccountType" -FileCategoryObject $FC_All
                    $CreationMethod = PoSHPACLI_GetFileCategoryValue -FileCategoryName "CreationMethod" -FileCategoryObject $FC_All
                    $Dependencies = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Dependencies" -FileCategoryObject $FC_All

                    #ExtraPass3Name	Operating System-P_DOM_INT_UNM-cxcorp.local-administrator
                    $ExtraPass3Name = PoSHPACLI_GetFileCategoryValue -FileCategoryName "ExtraPass3Name" -FileCategoryObject $FC_All

                    if($DiscoveryPlatformType -eq "Windows Server Local" -or $DiscoveryPlatformType -eq "Windows Domain"){
                        $Domain = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Domain" -FileCategoryObject $FC_All
                        $UserDisplayName = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UserDisplayName" -FileCategoryObject $FC_All
                        $OU = PoSHPACLI_GetFileCategoryValue -FileCategoryName "OU" -FileCategoryObject $FC_All
                        $SID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "SID" -FileCategoryObject $FC_All
                        $DeviceType = "Operating System"
                    }
                    if($DiscoveryPlatformType -eq "Unix" -or $DiscoveryPlatformType -eq "Unix SSH Key"){
                        $UID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "UID" -FileCategoryObject $FC_All
                        $GID = PoSHPACLI_GetFileCategoryValue -FileCategoryName "GID" -FileCategoryObject $FC_All
                        $DeviceType = "Operating System"
                    }
                    if($DiscoveryPlatformType -eq "Unix SSH Key"){
                        $Fingerprint = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Fingerprint" -FileCategoryObject $FC_All
                        $Length = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Length" -FileCategoryObject $FC_All
                        $Path = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Path" -FileCategoryObject $FC_All
                        $Format = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Format" -FileCategoryObject $FC_All
                        $Comment = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Comment" -FileCategoryObject $FC_All
                        $Encryption = PoSHPACLI_GetFileCategoryValue -FileCategoryName "Encryption" -FileCategoryObject $FC_All
                        $DeviceType = "Operating System"
                    }

                
                    $Output = $OutputFormat -f $UserName,$Address,$AccountDiscoveryDate,$AccountEnabled,$AccountOSGroups,$DiscoveryPlatformType,$LastPasswordSetDate,$LastLogonDate,$PasswordNeverExpires,$AccountExpirationDate,$OSVersion,$AccountCategory,$MachineOSFamily,$AccountType,$CreationMethod,$Dependencies,$Domain,$UserDisplayName,$OU,$SID,$UID,$GID,$Fingerprint,$Length,$Path,$Format,$Comment,$Encryption,$DeviceType,$SafeName,$Folder,$FileName,"","",$Name,$ExtraPass3Name
                    $Output | Out-file -FilePath $outputpath -Append


                    $PercComplete = [math]::Round(($RowNum / $CountOfRows) * 100)
                    Write-Progress -Activity "$RowNum objects scanned of $CountOfRows objects." -Status "$PercComplete% Complete:" -PercentComplete $PercComplete

                }
            }
        
        }

        PoSHPACLI_DisconnectVault
    }
    if($null -ne $item.Reports_Safe -and $item.Reports_Safe.Length -ne 0){
        #Move file to safe
        LogMessage -message "File created. Now moving file to vault"
        $uploadPath = (Get-ChildItem -Path $outputpath).FullName
        PoSHPACLI_UploadFile -VaultName $VaultConfig.vaultname `
            -Usr $appUsr `
            -password $PwdC -AsSecureString `
            -VaultAddress $VaultConfig.vaultip `
            -sessionid $VaultConfig.sessionid `
            -PACLI_EXE $VaultConfig.pacliexe `
            -TargetFolder $item.Reports_Folder `
            -TargetSafe $item.Reports_Safe `
            -inputpath $uploadPath
    }
}