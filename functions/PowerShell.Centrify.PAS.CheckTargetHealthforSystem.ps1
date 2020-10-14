<#
.Name
Centrify.PowerShell.PAS.Check-TargetHealthforSystem.ps1

.Sample 
Check-TargetHealthforSystem -endpoint $endpoint -bearerToken $token.bearerToken -domainName "centrify.lab.tr" -Verbose

Copyright 2019 by written http://www.rebuiltarchitect.com
#>


function Check-TargetHealthforSystem {
   
    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $domainName       
    )


        #get domainID
        Write-Verbose "geting domainID parameter for $domainName domain"
        $getdomainID= Centrify-GetDomainID -Endpoint $endpoint -Token $BearerToken -Domain $domainName -Verbose:$enableVerbose
        Write-Verbose  "$domainName, domainID: $getdomainID"
       
        Write-Verbose "geting all servers parameters for $domainName"
        #get all server parameters
        $query = "select * from server where domainID= '$getdomainID'"
        $queryjs = @{ 'script' = $query}
        $restResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryjs  -Verbose:$enableVerbose
        Write-Verbose ("Total number for $domainName : " + $restResult.result.results.count)


foreach ( $server in  $restResult.result.results.row){
   
    $restArg = @{}
    $restArg.ID = $server.ID
    $restArg.TargetType= "Computer"  
    $restResult = Centrify-InvokeREST -Method "/ServerManage/CheckTargetHealth" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
    Write-Verbose "Checked for $server.ID"

}    if($restResult.success -ne $true)
    {
        throw "Server error: $($restResult.Message)"
    }     
    
    return $restResult.Result.Apps
}
