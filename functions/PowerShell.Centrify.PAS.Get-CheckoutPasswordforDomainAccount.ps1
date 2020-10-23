<#
.Name
Centrify.PowerShell.PAS.Get-CheckoutPasswordforDomainAccount.ps1
 
.Sample 
Get-CheckoutPasswordforDomainAccount -endpoint $endpoint -bearerToken $token.bearerToken -domainName "centrify.lab.tr" -Verbose
 
Copyright 2020 by written http://www.rebuiltarchitect.com
#>
 
 
function Get-CheckoutPasswordforDomainAccount {
   
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
        $query = "select * from VaultAccount where domainID= '$getdomainID'"
        $queryjs = @{ 'script' = $query}
        $queryResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryjs  -Verbose:$enableVerbose
        Write-Verbose ("Total number of domain account for $domainName : " + $queryResult.result.results.count)
 
        $WorkFile = "$RootDirdata\Get-CheckoutPasswordforDomainAccount.csv"
         
foreach ( $account in  $queryResult.result.results.row){
   
    $restArg = @{}
    $restArg.ID = $account.ID
    $restResult = Centrify-InvokeREST -Method "/ServerManage/CheckoutPassword" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose
 
   # Collect the results
     $item = @{}
     $item.username = $account.user
     $item.password = $restResult.Result.Password
     $collection = New-Object psobject -Property $item
     # Set work file
 
    # Write the results and view
    $collection |Select-Object username, password| Export-Csv -LiteralPath $WorkFile -NoTypeInformation –Append  -Encoding UTF8 
 
} 
 
 
 
 
 
# if($restResult.success -ne $true)
#   {
  #      throw "Account error: $($restResult.Message)"
   # }   
    return $restResult.Result.Apps
}
