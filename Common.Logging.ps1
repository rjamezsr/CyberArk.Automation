. .\Common.Utils.ps1 
. .\Common.Config.ps1

$VAR_FILEFORMAT_LOG     = "Log"
$VAR_FILEFORMAT_ERROR   = "Error"
$PATH_LOG_DIR           =(Load-Config -Path $PATH_GLOBAL_CONFIG).Environment.Directory.Logging
$EXT_LOGGING            = ($ConfigDataJSON.FileFormats | `
                            Where Name -eq (($ConfigDataJSON.Environment.Files | Where Name -eq $VAR_FILEFORMAT_LOG `
                                | Select FileFormat).FileFormat)).Format.FileTypeExtension

$PATH_LOG_FILENAME      = ($ConfigDataJSON.FileFormats | `
                            Where Name -eq (($ConfigDataJSON.Environment.Files | Where Name -eq $VAR_FILEFORMAT_LOG `
                                | Select FileFormat).FileFormat)).Format.FileTypeExtension

$PATH_LOG               ="$PATH_LOG_DIRECTORY\\Log.$EXT_LOGGING"
$PATH_LOG_ERROR         ="$PATH_LOG_DIRECTORY\\error.$EXT_LOGGING"
$VAR_DELIMITER          = ","
$VAR_INFO               = "INFO"
$VAR_WARNING            = "WARNING"
$VAR_ERROR              = "ERROR"
function Log-Message {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $message,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $error,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $info,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $warning
    )
    
    process {
        if($error){
            $Msg = Get-Message -message $message -error
        }elseif ($warning){
            $Msg = Get-Message -message $message -warning
        }elseif ($info){
            $Msg = Get-Message -message $message -info
        }
        Write-Verbose $Msg
        $Path = if($error){$PATH_LOG_ERROR}else{$PATH_LOG}
        if(Append-ToFile -Path $Path -Text $Msg -Force){
            $true
        }else{
            Write-Verbose "Could not write to log file"
            $false
        }
    }
}
function Get-Message {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $message,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $error,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $info,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $warning
    )
    process {
        $DateTime = Get-Date
        $MsgPrefix = ""
        if($error){
            $MsgPrefix = Get-MessagePrefix -error
        }elseif ($warning){
            $MsgPrefix = Get-MessagePrefix -warning
        }elseif ($info){
            $MsgPrefix = Get-MessagePrefix -info

        }
        $MsgText = "{0}$VAR_DELIMITER{1}" -f $MsgPrefix, $message
        $Msg = "{0}$VAR_DELIMITER{1}" -f $DateTime,$MsgText
        $Msg
    }
}
function Get-MessagePrefix {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $error,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $info,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $warning
    )
    process {
        if($error){
            $VAR_ERROR
        }elseif ($warning) {
            $VAR_WARNING
        }elseif ($info){
            $VAR_INFO
        }
    }
}