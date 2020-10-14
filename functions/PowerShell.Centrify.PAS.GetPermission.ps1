<# 
 .Name
  PowerShell.Centrify.PAS.AddAccountFromActiveDirectory.ps1

 .Synopsis
  Performs a REST call against the CIS platform.  

 .Description
  Performs a REST call against the CIS platform (JSON POST)

 .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrifylab.com)
 
 .Parameter Method
  Required - The method to call (i.e. /security/logout)
  
 .Parameter Token
  Optional - The bearer token retrieved after authenticating, necessary for 
  authenticated calls to succeed.
  
 .Parameter DomainName
  Optional - A powershell object which will be provided as the POST arguments
  to the API after passing through ConvertTo-Json.  Overrides JsonContent.
  
  .Parameter TargetType
  Optional - A string which will be posted as the application/json body for
  the call to the API.

 .Example
   # Add account from Active Directory

   CheckTargetHealth -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrifylab.com" -TargetType "Computer" -Verbose

   CheckTargetHealth -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrifylab.com" -TargetType "Database" -Verbose

   Copyright 2020 by written Oguz Kalfaoglu from CentrifyLab
#>


$logfile = "$PSScriptRoot\..\logs\CheckTargetHealth.log"

function GetPermission {


    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $domainName
    )

 

 try{ 

   Write-Log "====================================================Started================================================"  $logfile "DEBUG" 

     #get domainID
     Write-Log "geting domainID parameter for $domainName domain" $logfile "DEBUG"
     $getdomainID= Centrify-GetDomainID -Endpoint $endpoint -Token $BearerToken -Domain $domainName -Verbose:$enableVerbose
     Write-Log  "$domainName, domainID: $getdomainID" $logfile "DEBUG"

     Write-Log  "geting all servers parameters for $domainName"  $logfile "DEBUG"
     #get all server parameters
     $query = "select * from VaultAccount where user='srvc.centrifypas' and domainID= '$getdomainID'"
     $queryjs = @{ 'script' = $query}
     $restResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryjs  -Verbose:$enableVerbose
     Write-Log ("Total number server for $domainName : " + $restResult.result.results.count) $logfile "DEBUG"
       

     foreach ( $target in  $restResult.result.results.row){ 
 
     $vaultJson='{"RowKey":"'+$target.ID+'","Table":"VaultAccount","ReduceSysadmin":true,"Args":{"PageNumber":1,"PageSize":100000,"Limit":100000,"SortBy":"","direction":"False","Caching":-1}}'
     $vaultResult = Centrify-InvokeREST -Method "/Acl/GetRowAces" -Endpoint $endpoint -Token $bearerToken -jsonContent $vaultJson -Verbose:$enableVerbose
     Write-Log "Checked for $vaultResult.Result.AceId" $logfile "DEBUG"

       foreach ( $AceID in  $vaultResult.Result.AceId){ 
        $aceArg = @{}
        $aceArg.ID = $AceID
        $aceResult = Centrify-InvokeREST -Method "/Acl/GetAce" -Endpoint $endpoint -Token $bearerToken -ObjectContent $aceArg -Verbose:$enableVerbose
        
        $PrincipalID = $aceResult.Result.Principal

        $queryvault = "select UserPrincipalName from ADUser where ObjectGUID='$PrincipalID'"
        $queryvaultyjs = @{ 'script' = $queryvault}
        $queryvaultResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryvaultyjs  -Verbose:$enableVerbose

        $reqPermissions=@{}
        $reqPermissions.Account = $restResult.Result.Results.Row.User
        $reqPermissions.AccountID = $restResult.Result.Results.Row.ID
        $reqPermissions.PermissionName = $queryvaultResult.Result.Results.Row.UserPrincipalName
        $reqPermissions.PermissionNameID = $aceResult.Result.Principal
        $reqPermissions.PermissionNameRights = $aceResult.Result.Rights.Grant       
        }

     }

    }  
    catch
        {
            Write-Log  "Error : $($_.Exception.Message)" $logfile "DEBUG" 
        }

  return $restResult.Result.Apps

  Write-Log "====================================================Finished================================================"  $logfile "DEBUG" 
 }