. .\Common.ps1
function Create-ValidationResultObject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $ValidationMethod,
        [Parameter(ValueFromPipelineByPropertyName)]
        $data,
        [Parameter(ValueFromPipelineByPropertyName)]
        $validData,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [boolean]
        $IsValid

    )
    process {
        [PSCustomObject]@{
            ValidationMethod    = $ValidationMethod | ConvertTo-Json
            IsValid             = $IsValid
            Data                = $data
            ValidData           = $validData
        }
    }
}
function Create-ValidationResultDataObject {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ValidationTaskName,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $ValidationTaskDescription,
        [Parameter(ValueFromPipelineByPropertyName)]
        $data

    )
    process {
        [PSCustomObject]@{
            Name            = $ValidationTaskName
            Description     = $ValidationTaskDescription
            Data            = $data
        }
    }
}
function Execute-ValidationMethod {
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $config,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $ValidationTask,
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [object]
        $ValidationMethod,
        [Parameter(ValueFromPipelineByPropertyName)]
        $data

    )
    process {
        $validationObject = $null
        $ret = $false
        $evaluateExpressionFormat = "{0} -{1} {2}"
        $commandResults = [System.Collections.ArrayList]@()
        $validResults = [System.Collections.ArrayList]@()

        $failureMessage = $ValidationMethod.failureMessage
        
            

        if($null -ne $data){
            try {
                $command = ($config.Methods | Where-Object {$_.Name -eq $ValidationMethod.method}).command
                $evaluate = $ValidationMethod.evaluate
                $operation = $ValidationMethod.operation
                $value = $ValidationMethod.value
                $result = $ValidationMethod.result -eq "true"
                $commandresult = Invoke-Expression -Command $command
                
                $commandresultRows = ($commandresult | Measure-Object).Count
                LogMessage -message "Validation command returned $commandresultRows rows"
                
                $evaluateExpression = $evaluateExpressionFormat -f $evaluate,$operation,$value
                $evaluateResultValue = $true



                $commandresult | Foreach-Object {
                    
                    $evaluateResult = Invoke-Expression -Command $evaluateExpression
                    $ret = $evaluateResult -eq $result
                    if($ret -eq $false) {
                        $evaluateResultValue=$false
                        $resultDataObject = Create-ValidationResultDataObject -ValidationTaskName $ValidationTask.Name `
                            -ValidationTaskDescription $ValidationTask.Description `
                            -data $_

                        if($null -ne $failureMessage){
                            $failureMessage = $failureMessage -replace "{method}",$ValidationMethod.method
                            $failureMessage = $failureMessage -replace "{value}",$ValidationMethod.value
                            $failureMessage = $failureMessage -replace "{taskname}",$ValidationTask.Name
                            LogMessage -message $failureMessage
                        }

                        [void]$commandResults.Add($resultDataObject)
                    }else{
                        [void]$validResults.Add($_)
                    }
                }
                $validationObject = Create-ValidationResultObject -IsValid $evaluateResultValue -ValidationMethod $ValidationMethod -data $commandResults -validData $validResults
            } catch {
                LogMessage -message $Error[0]
            }
        }
        $validationObject
    }
    
}
Function Validate-QueryData {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (
        [ValidateScript({ Test-Path -Path $_})][string]
        $ConfigData,
        [Parameter(ValueFromPipelineByPropertyName)]
        $data

    )
    process {
        $validationResults = [System.Collections.ArrayList]@()
        $config = Get-Content $ConfigData | ConvertFrom-Json 
        $config.ValidationTasks | Foreach-object {
            $task = $_
            $taskName = $task.Name
            $task.ValidationMethods | ForEach-Object {
                $validationMethod = $_
                $stopIfNotValid = $validationMethod.stopIfNotValid -eq "Yes"
                $validationResultObject = Execute-ValidationMethod -config $config `
                    -ValidationTask $task `
                    -ValidationMethod $validationMethod `
                    -data $data

                
                [void]$validationResults.Add($validationResultObject)
                

                if($validationResultObject.IsValid -eq $false -and $stopIfNotValid){
                    $methodName = $validationMethod.method
                    LogMessage -message "Validation task '$taskName' has been aborted. Method '$methodName' has failed and is configured to stop all methods that follow."
                    break                      
                }
                
                # if($validationResultObject.IsValid -eq $false){
                #     [void]$validationResults.Add($validationResultObject)
                # }
                
            }
            
        }
        $validationResults
    }
}
Function Export-ValidationReport {
    [CmdletBinding()]
    [OutputType([boolean])]
    param (


        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [string]
        $Outputpath,
        [Parameter(Mandatory = $true,
        ValueFromPipelineByPropertyName = $true,
        Position = 0)]
        [object]
        $ValidationObject

    )
    process {
        $ret = $false
        $report = [System.Collections.ArrayList]@()
        try {
            if(Test-Path -Path $Outputpath){
                Remove-Item -Path $Outputpath
            }
            $ValidationObject.Data | Foreach-Object {
                [void]$report.Add([pscustomobject]@{
                    Name = $_.Name;
                    Description = $_.Description;
                    DataValue = $_.Data 
                })
            }
            $report | Select Name,Description,DataValue | Export-Csv -Path $Outputpath -NoTypeInformation
        } catch {
            LogMessage -message $Error[0]
        }
        $ret = Test-Path -Path $Outputpath
        $ret

    }
}