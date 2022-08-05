. .\Common.ps1
. .\Common.Users.ps1
Function Send-Message {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [ValidateScript({ Test-Path -Path $_})][string]
        $ConfigPath,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $subject="",
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $body="",
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $recipient="",
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $template=$null,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $SubjectParams = $null,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $BodyParams = $null
    )
    process {
        $sent = $false
        if($null -ne $template){
            $sent = Send-MessageFromTemplate -ConfigPath $ConfigPath -template $template -SubjectParams $SubjectParams -BodyParams $BodyParams
        }else{
            $config = Get-Content $ConfigPath | ConvertFrom-Json 
            
            try {

                $sender = $config.SMTPSettings.SenderAddress
                $server = $config.SMTPSettings.SMTPServer
                $port = $config.SMTPSettings.SMTPPort
                
                Send-MailMessage -From $sender `
                    -To $recipient -Subject $subject `
                    -Body $body -SmtpServer $server `
                    -Port $port -ErrorAction Stop
    
                $sent = $true
            } catch {
                LogMessage -message $Error[0]
            }
        }
        
        $sent

    }
}
Function Send-MessageFromTemplate {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [ValidateScript({ Test-Path -Path $_})][string]
        $ConfigPath,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $template,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $SubjectParams = $null,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $BodyParams = $null

    )
    process {
        $sent = $false
        $recipients = $template.Recipients
        $subject = $template.Subject
        $body = $template.Body
        if($null -ne $SubjectParams){
            $subject = $template.Subject -f $SubjectParams
        }
        if($null -ne $BodyParams){
            $body = $template.Body -f $BodyParams
        }
        if($null -ne $template.RecipientsCyberArkGroup -and $template.RecipientsCyberArkGroup -ne ""){
            $recipients = Get-CyberArkRecipientsByGroup -ConfigPath $ConfigPath -groupname $template.RecipientsCyberArkGroup
        }
        $sent = Send-Message -ConfigPath $ConfigPath `
            -subject $subject `
            -body $body `
            -recipient $recipients
        
        $sent

    }
}
function Get-CyberArkRecipientsByGroup {
    param (
        [ValidateScript({ Test-Path -Path $_})][string]
        $ConfigPath,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $groupname

    )
    $members = Get-UsersByGroup -ConfigPath $ConfigPath -groupname $groupname
    $members.Email -join ","
}
