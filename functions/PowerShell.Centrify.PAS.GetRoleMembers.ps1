<# 
 .Name
  PowerShell.Centrify.PAS.GetRoleMembers.ps1

 .Synopsis
  This script get the rolemembers from the Centrify PAS  

 .Description
  This script get the rolemembers from the Centrify PAS (JSON POST)

 .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrifylab.com)
 
 .Parameter Method
  Required - The method to call (i.e. /security/logout)
  
 .Parameter Token
  Optional - The bearer token retrieved after authenticating, necessary for authenticated calls to succeed.
  
 .Parameter RoleName
  Required - The method to read Role table 


 .Example
  GetRoleMembers -endpoint $endpoint -bearerToken $token.BearerToken -roleName "MFA Role for Computers" -Verbose

  Copyright 2020 by written Oguz Kalfaoglu from CentrifyLab© and RebuiltArchitect©
#>


function GetRoleMembers {

    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $roleName        
    )

  $logfile = "$PSScriptRoot\..\logs\GetRoleMembers.log"

  Write-Log "==================================================== Started Log File for GetRoleMembers Function ================================================"  $logfile "DEBUG" 
 
  try{

    #get all server parameters
    $query = "select ID from Role where name= '$roleName'"
    $queryjs = @{ 'script' = $query}
    $queryResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryjs  -Verbose:$enableVerbose
    
    $roleID=$queryResult.Result.Results.Row.ID

    Write-Log "$roleID of $roleName Role ID." $logfile "DEBUG"     
    
    $restArg = @{}     
    
    $restResult = Centrify-InvokeREST -Method "/saasmanage/GetRoleMembers?name=$roleID" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
    if($restResult.success -ne $true)
    {
        throw "Server error: $($restResult.Message)"
    }     
    #Export the result Array to CSV file  
    $restResult.Result.Results.Row | Select-Object Name | Export-Csv -Path "$PSScriptRoot\..\data\GetRoleMembers.csv"  

    }
    catch{
    
         Write-Log  "Error : $($_.Exception.Message)" $logfile "DEBUG" 

          }
    Write-Log "==================================================== Finished Log File for GetRoleMembers Function ================================================"  $logfile "DEBUG" 

    return $restResult.Result.Results.Row.Name

}
