$VAR_DELIMITER_DIR  = "\\"
$VAR_EMPTYSTRING    = ""
function Append-ToFile {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Text,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Path,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $Force
    )
    
    process {
        if($Force){
            Write-ToFile -Path $Path -Text $Text -Append -Force
        }else{
            Write-ToFile -Path $Path -Text $Text -Append
        }
        
    }
    
}
function Write-ToFile{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Text,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Path,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $Append,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $Force

    )
    process {
        
        $fileExists = $null -ne (Get-FilePath -Path $Path)
        if($fileExists -eq $false -and $Force){
            $fileExists = $null -ne (Get-FilePath -Path $Path -CreateIfNotExist)
        }
        if($fileExists){
            if($Append){
                Write-ToFileAppend -Text $Text -Path $Path   
            }else{
                Write-ToFileReplace -Text $Text -Path $Path
            }
        }else{
            $false
        }
    }
    
}
function Get-FilePath{
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Path,
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [switch]
        $CreateIfNotExist
    )
    process 
    {
        Write-Verbose "Get File Path '$Path'"
        try {
            $result = $null
            if(Test-Path $Path){
                $result = $Path
            }elseif ($CreateIfNotExist){
                if(Create-File -Path $Path){
                    $result = $Path
                }
            }
            $result
        } catch {
            $msg = $_.Exception
            $msg = "Could not create file. {0}"  -f $msg
            Write-Verbose $msg
            $result
        }
    }
}

function Create-File {
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Path
    )

    process {
        Write-Verbose "Creating file '$Path'"
        try {
            New-Item -Path $Path -ErrorAction Stop | Out-Null
            $true
        } catch {
            $msg = $_.Exception
            $msg = "Could not create file. {0}" -f $msg
            Write-Verbose $msg
            $false
        }
    }
}
function Write-ToFileReplace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Text,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]                   
        [string]
        $Path
    )
    process {
        Write-Verbose "Replace file '$Path'"
        try {
            $Text | Out-File -FilePath $Path -encoding ASCII   
            $true
        } catch {
            $msg = $_.Exception
            Write-Verbose $msg
            $false
        }
        
    }
    
}
function Write-ToFileAppend {
    param (
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Text,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [ValidateScript({Test-Path $_})]                   
        [string]
        $Path
    )
    process {
        Write-Verbose "Append to file '$Path'"
        try {
            $Text | Out-File -FilePath $Path -Append -encoding ASCII 
            $true
        } catch {
            $msg = $_.Exception
            Write-Verbose $msg
            $false
        }
    } 
}
