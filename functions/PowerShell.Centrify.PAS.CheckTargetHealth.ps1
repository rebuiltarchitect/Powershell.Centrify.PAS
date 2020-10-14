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




function CheckTargetHealth {


    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $domainName,
        [Parameter(Mandatory=$true)]
        $targetType
    )

  $logfile = "$PSScriptRoot\..\logs\CheckTargetHealth.log"

  Write-Log "==================================================== Started Log File for CheckTargetHealth Function ================================================"  $logfile "DEBUG" 
 try{ 


        if ($targetType -eq "Computer") {
        #get domainID
        Write-Log "geting domainID parameter for $domainName domain" $logfile "DEBUG"
        $getdomainID= Centrify-GetDomainID -Endpoint $endpoint -Token $BearerToken -Domain $domainName -Verbose:$enableVerbose
        Write-Log  "$domainName, domainID: $getdomainID" $logfile "DEBUG"

        Write-Log  "geting all servers parameters for $domainName"  $logfile "DEBUG"
        #get all server parameters
        $query = "select * from server where domainID= '$getdomainID'"
        $queryjs = @{ 'script' = $query}
        $restResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryjs  -Verbose:$enableVerbose
        Write-Log ("Total number server for $domainName : " + $restResult.result.results.count) $logfile "DEBUG"
       
        } 


        foreach ( $target in  $restResult.result.results.row){
            $restArg = @{}
            $restArg.ID = $target.ID
            $restArg.TargetType=  $targetType  
            $restResult = Centrify-InvokeREST -Method "/ServerManage/CheckTargetHealth" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
            Write-Log "Checked for $target.ID" $logfile "DEBUG"

        }   



    }  
    catch
        {
            Write-Log  "Error : $($_.Exception.Message)" $logfile "DEBUG" 
        }

  Write-Log "==================================================== Finished Log File for CheckTargetHealth Function ================================================"  $logfile "DEBUG" 

 }