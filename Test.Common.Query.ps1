[CmdletBinding()]
param()


. .\Common.Query.ps1 

$config = Get-Content -Path "C:\\repo\\Azure.DevOps\\Prolab-IDM\\CyberArk.Automation.Config\\Manual\\GetAccountManagementStatus_PSPAS.json" | ConvertFrom-Json
$data = Import-Csv "C:\\data\\Safes.csv"

Write-Verbose "Query before filter"
$data

Write-Verbose "Filter"
$filterExp = Create-FilterExpression -filters $config.GetAccountsPSPAS.Safes.FilterSafes
$filterExp

Write-Verbose "Query after filter"
$data | Where-Object $filterExp

#Create-FilterExpression -filters $config.GetAccountsPSPAS.Safes.FilterSafes