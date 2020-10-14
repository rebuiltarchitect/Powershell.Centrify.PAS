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
  
 .Parameter OU
  Optional - A string which will be posted as the application/json body for
  the call to the API.

  .Parameter SetName
  Optional - A string which will be posted as the application/json body for
  the call to the API.

 .Example
   # Add account from Active Directory

   AddAccountFromActiveDirectory -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrifylab.com" -OU "OU=Users,OU=Windows,OU=Centrify,DC=centrifylab,DC=com" -setsName "Active Directory Service Accounts" -Verbose

   Copyright 2020 by written Oguz Kalfaoglu from CentrifyLab
#>


$logfile = "$PSScriptRoot\..\logs\AddAccountFromActiveDirectory.log"



function AddAccountFromActiveDirectory {


    param(
        [Parameter(Mandatory=$true)]
        $endpoint,
        [Parameter(Mandatory=$true)]
        $bearerToken,
        [Parameter(Mandatory=$true)]
        $domainName,
        [Parameter(Mandatory=$true)]
        $ou,
        [Parameter(Mandatory=$true)]
        $setsName
    )
 
  Write-Log "====================================================Started================================================"  $logfile "DEBUG" 
 try{ 
  
	
    $DomainID= Centrify-GetDomainID -endpoint $endpoint -domainName $domainname -token $bearerToken
    Write-Log  "DomainID: $DomainID is setting"  $logfile "DEBUG" 
     
    $ADUser = Get-ADUser -Filter * -SearchBase $OU -Properties * -Server $domainName
}
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
         {
          Write-Log  "Get-ADUser function doesn't exist" $logfile "DEBUG"
         }

foreach ($user in $ADUser) {

 try{  
    $restArg = @{}
    $restArg.User = $user.sAMAccountName
    $restArg.Password = '' # Adding password null
    $restArg.IsManaged = 'FALSE' #Do not manage accounts
    $restArg.UseWheel = "false"
    $restArg.Description = "$($user.Description)"
    $restArg.DomainID = $DomainID    
    $restResult = Centrify-InvokeREST -Method "/ServerManage/AddAccount" -Endpoint $endpoint -Token $bearerToken -ObjectContent $restArg -Verbose:$enableVerbose 
    Write-Log "AddAccount Result: Success?s $($restResult.success). $($user.sAMAccountName) $($restResult.Message) $($restResult.InnerExceptions.Message)" $logfile "DEBUG"    

    
    $restArg2= '{"ObjectType":"VaultAccount","NoBuiltins":true}'
    $restResult2 = Centrify-InvokeREST -Method "/Collection/GetObjectCollectionsAndFilters" -Endpoint $endpoint -Token $bearerToken -jsonContent $restArg2 -Verbose:$enableVerbose 
    Write-Log  "GetObjectCollectionsAndFilters Result: Success? $($restResult2.success). $($restResult2.Message) $($restResult2.InnerExceptions.Message)"  $logfile "DEBUG" 
        
    $setsrow= ($restResult2.Result.Results.Row) | Where-Object {$_.Name -eq "$setsName"}
    $setsid= $setsrow.ID
    
     $accountid= Centrify-GetAccountID -endpoint $endpoint -domainName $domainName  -accountName $user.sAMAccountName -token $bearerToken
    $restArg3 ='{"id":"'+$setsid+'","add":[{"MemberType":"Row","Table":"VaultAccount","Key":"'+ $accountid+'"}]}'
    $restResult3 = Centrify-InvokeREST -Method "/Collection/UpdateMembersCollection" -Endpoint $endpoint -Token $bearerToken -jsonContent $restArg3 -Verbose:$enableVerbose
    Write-Log  "UpdateMembersCollection Result: Success? $($restResult3.success). $($restResult3.Message) $($restResult3.InnerExceptions.Message)" $logfile "DEBUG" 
}  
    catch
        {
            Write-Log  "Error : $($_.Exception.Message)" $logfile "DEBUG" 
        }

  }

  Write-Log "====================================================Finished================================================"  $logfile "DEBUG" 
 }

  