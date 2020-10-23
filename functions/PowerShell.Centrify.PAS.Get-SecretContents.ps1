[CmdletBinding()]
param(
    #Used for interactive auth only. Comment out for OAuth
    #[Parameter(Mandatory=$true)]
    #[string]$username = "",
    [string]$endpoint = "https://pas.intertech.com.tr"
)

# Get the directory the example script lives in
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
write-host $RootDir

# Import the Centrify.Samples.Powershell  and Centrify.Samples.PowerShell.CPS modules 
 Import-Module $RootDir\modules\PowerShell.ConnectRestApi.psm1 3>$null 4>$null
 Import-Module $RootDir\modules\PowerShell.Centrify.PAS.Import.psm1 3> $null 4>$null
 Import-Module $RootDir\modules\PowerShell.Centrify.PAS.Export.psm1   3> $null 4>$null
 Import-Module $RootDir\modules\PowerShell.Logger.psm1   3> $null 4>$null

# If Verbose is enabled, we'll pass it through
$enableVerbose = ($PSBoundParameters['Verbose'] -eq $true)

# Import sample function definitions


. $RootDir\functions\PowerShell.Centrify.PAS.AddAccountFromActiveDirectory.ps1
. $RootDir\functions\PowerShell.Centrify.PAS.CheckTargetHealth.ps1
. $RootDir\functions\PowerShell.Centrify.PAS.GetPermission.ps1


try{
    #Authorization using OAuth2 Cleint Credentials Flow. If interactive or MFA is desired, use OnDemandChallenge APIs https://developer.centrify.com/reference#post_security-ondemandchallenge
    #$token = Centrify-OAuth-ClientCredentials -Endpoint $endpoint -Appid "Automation" -Clientid "pasadmin@centrify.local" -Clientsecret "24Qwert12" -Scope "Account" -Verbose:$enableVerbose    
    #$token = Centrify-OAuth-ClientCredentials -Endpoint $endpoint -Appid "automation" -Clientid "automationuser@centrify.local" -Clientsecret "24Qwert12" -Scope "all" -Verbose:$enableVerbose    
    $token = Centrify-OAuth-ClientCredentials -Endpoint "https://pas.intertech.com.tr" -Appid "automation" -Clientid "automation@centrify.local" -Clientsecret "XvddcZLrNaA9uo" -Scope "all" -Verbose:$enableVerbose    
    # $token = Centrify-OAuth-ClientCredentials -Endpoint $endpoint -Appid "Automation" -Clientid "pasadmin@centrify.local" -Clientsecret "24Qwert12" -Scope "Account" -Verbose:$enableVerbose    
    # Get information about the user who owns this token via /security/whoami     
    $userInfo = Centrify-InvokeREST -Endpoint $token.Endpoint -Method "/security/whoami" -Token $token.BearerToken -Verbose:$enableVerbose     
    Write-Host "Current user: " $userInfo.Result.User

    # Add User to a CPS Resource
    # UpdatePasswordWithCvsFile -Endpoint $token.Endpoint -BearerToken $token.BearerToken -csvFile "C:\Util\denizbank\data\user.csv" -Verbose    
    # Set-PermissionWithCvsFile  -Endpoint $token.Endpoint -BearerToken $token.BearerToken -csvFile "C:\Util\denizbank\data\SetPermission.csv" -Verbose 
    # UpdateResource -Endpoint $token.Endpoint -BearerToken $token.BearerToken -Verbose
    # AddAccount -endpoint $endpoint -bearerToken $token.bearerToken -username "lcwuser2d" -password "24Qwert12" -Description "aa" -IsManaged "false" -DatabaseName "da01w19" -operation "Database" -Verbose
    # AddAccount -endpoint $endpoint -bearerToken $token.bearerToken -username "lcwuser2" -password "24Qwert12" -Description "aa" -IsManaged "true" -HostName "pa01w19.centrify.lab.tr" -operation "System" -Verbose
    # AddAccount -endpoint $endpoint -bearerToken $token.bearerToken -username "srvc.prt01" -password "@3J<lbds6W" -domainName "centrify.lab.tr" -Description "aa" -IsManaged "true" -operation "Domain" -Verbose
    # Update-Resource -endpoint $endpoint -bearerToken $token.bearerToken -domain "centrify.lab.tr"
      
    # AddAccountFromActiveDirectory -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrify.lab.tr" -OU "OU=Users,OU=Windows,OU=Centrify,DC=centrify,DC=lab,DC=tr" -setsName "Active Directory Service Accounts" -Verbose
    # CheckTargetHealth -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrify.lab.tr" -TargetType "Domain" -Verbose
    # GetPermission -endpoint $endpoint -bearerToken $token.BearerToken -domainName "centrify.lab.tr" -Verbose
    # GetRoleMembers -endpoint $endpoint -bearerToken $token.BearerToken -roleName "MFA Role for Computers" -Verbose
    # Get-CheckoutPasswordforDomainAccount -endpoint $endpoint -bearerToken $token.BearerToken  -Verbose
      Get-SecretContents -endpoint $endpoint -bearerToken $token.BearerToken  -Verbose
}
finally
{
    # Always remove the Centrify.Samples.Powershell and Centrify.Samples.Powershell.CPS modules, makes development iteration on the module itself easier
     Remove-Module PowerShell.ConnectRestApi 4>$null
     Remove-Module PowerShell.Centrify.PAS.Import 4>$null
     Remove-Module PowerShell.Centrify.PAS.Export 4>$null
     Remove-Module PowerShell.Logger 4>$null
}
