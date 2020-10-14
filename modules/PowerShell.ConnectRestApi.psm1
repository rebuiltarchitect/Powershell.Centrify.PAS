<# 
 .Synopsis
  Performs a REST call against the CIS platform.  

 .Description
  Performs a REST call against the CIS platform (JSON POST)

 .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)
 
 .Parameter Method
  Required - The method to call (i.e. /security/logout)
  
 .Parameter Token
  Optional - The bearer token retrieved after authenticating, necessary for 
  authenticated calls to succeed.
  
 .Parameter ObjectContent
  Optional - A powershell object which will be provided as the POST arguments
  to the API after passing through ConvertTo-Json.  Overrides JsonContent.
  
 .Parameter JsonContent
  Optional - A string which will be posted as the application/json body for
  the call to the API.

 .Example
   # Get current user details
   Centrify-InvokeREST -Endpoint "https://cloud.centrify.com" -Method "/security/whoami" 
#>
function Centrify-InvokeREST {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,
        [Parameter(Mandatory=$true)]
        [string] $method,        
        [string] $token = $null,
        $objectContent = $null,
        [string]$jsonContent = $null,       
        $websession = $null,
        [bool]$includeSessionInResult = $false,
        [System.Security.Cryptography.X509Certificates.X509Certificate] $certificate = $null
    )
    
    # Force use of tls 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                             
    $methodEndpoint = $endpoint + $method
    Write-Verbose "Calling $methodEndpoint"
    
    $addHeaders = @{ 
        "X-CENTRIFY-NATIVE-CLIENT" = "1"
    }
    
    if(![string]::IsNullOrEmpty($token))
    {        
        Write-Verbose "Using token: $token"
        $addHeaders.Authorization = "Bearer " + $token
    }
    
    if($objectContent -ne $null)
    {
        $jsonContent = $objectContent | ConvertTo-Json
    }
    
    if(!$jsonContent)
    {
        Write-Verbose "No body provided"
        $jsonContent = "[]"
    }

    if(!$websession)
    {
        Write-Verbose "Creating new session variable"
        if($certificate -eq $null)
        {
            $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonContent)) -SessionVariable websession -Headers $addHeaders
        }
        else 
        {
            $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonContent)) -SessionVariable websession -Headers $addHeaders -Certificate $certificate
        }
    }
    else
    {
        Write-Verbose "Using existing session variable $websession"
        if($certificate -eq $null)
        {
            $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonContent)) -WebSession $websession
        }
        else
        {            
            $response = Invoke-RestMethod -Uri $methodEndpoint -ContentType "application/json" -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonContent)) -WebSession $websession -Certificate $certificate
        }
        
    }
             
    if($includeSessionInResult)
    {             
        $resultObject = @{}
        $resultObject.RestResult = $response
        $resultObject.WebSession = $websession 
             
        return $resultObject
    }
    else
    {
        return $response
    }                        
}

<# 
 .Synopsis
  Performs a silent login using a certificate, and outputs a bearer token (Field name "BearerToken").

 .Description
  Performs a silent login using client certificate, and retrieves a token suitable for making
  additional API calls as a Bearer token (Authorization header).  Output is an object
  where field "BearerToken" contains the resulting token, or "Error" contains an error
  message from failed authentication. Result object also contains Endpoint for pipeline.

 .Parameter Endpoint
  The endpoint to authenticate against, required - must be tenant's url/pod

 .Example
   # Get a token for API calls to abc123.centrify.com
   Centrify-CertSsoLogin-GetToken -Endpoint "https://abc123.centrify.com" 
#>
function Centrify-CertSsoLogin-GetToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate] $certificate = $null        
    )
        
    $subject = $certificate.Subject
    Write-Verbose "Initiating Certificate SSO against $endpoint with $subject"
    $noArg = @{}
                     
    $restResult = Centrify-InvokeREST -Endpoint $endpoint -Method "/negotiatecertsecurity/sso" -Token $null -ObjectContent $startArg -IncludeSessionInResult $true -Certificate $certificate                    
    $startAuthResult = $restResult.RestResult                     
        
    # First, see if we need to repeat our call against a different pod 
    if($startAuthResult.success -eq $false)
    {            
        throw $startAuthResult.Message
    }
            
    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.WebSession.Cookies.GetCookies($endpoint)[".ASPXAUTH"].value
    
    Write-Output $finalResult        
}

<# 
 .Synopsis
  Performs an interactive MFA login, and outpus a bearer token (Field name "BearerToken").

 .Description
  Performs an interactive MFA login, and retrieves a token suitable for making
  additional API calls as a Bearer token (Authorization header).  Output is an object
  where field "BearerToken" contains the resulting token, or "Error" contains an error
  message from failed authentication. Result object also contains Endpoint for pipeline.

 .Parameter Endpoint
  The first month to display.

 .Example
   # MFA login to cloud.centrify.com
   Centrify-InteractiveLogin-GetToken -Endpoint "https://cloud.centrify.com" 
#>
function Centrify-InteractiveLogin-GetToken {
    [CmdletBinding()]
    param(
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [string] $username = ""    
    )
    
    Write-Verbose "Initiating MFA against $endpoint for $username"
    $startArg = @{}
    $startArg.User = $username
    $startArg.Version = "1.0"
                     
    $restResult = Centrify-InvokeREST -Endpoint $endpoint -Method "/security/startauthentication" -Token $null -ObjectContent $startArg -IncludeSessionInResult $true                     
    $startAuthResult = $restResult.RestResult                     
        
    # First, see if we need to repeat our call against a different pod 
    if($startAuthResult.success -eq $true -and $startAuthResult.Result.PodFqdn -ne $null)
    {        
        $endpoint = "https://" + $startAuthResult.Result.PodFqdn
        Write-Verbose "Auth redirected to $endpoint"
        $restResult = Centrify-InvokeREST -Endpoint $endpoint -Method "/security/startauthentication" -Token $null -ObjectContent $startArg -WebSession $restResult.WebSession -IncludeSessionInResult $true        
        $startAuthResult = $restResult.RestResult 
    }
    
    # Get the session id to use in handshaking for MFA
    $authSessionId = $startAuthResult.Result.SessionId
    $tenantId = $startAuthResult.Result.TenantId
    
    # Also get the collection of challenges we need to satisfy
    $challengeCollection = $startAuthResult.Result.Challenges
    
    # We need to satisfy 1 of each challenge collection            
    for($x = 0; $x -lt $challengeCollection.Count; $x++)
    {
        # Present the user with the options available to them
        for($mechIdx = 0; $mechIdx -lt $challengeCollection[$x].Mechanisms.Count; $mechIdx++)
        {            
            $mechDescription = Centrify-Internal-MechToDescription -Mech $challengeCollection[$x].Mechanisms[$mechIdx]
            Write-Host "Mechanism $mechIdx => $mechDescription" 
        }
                                
        [int]$selectedMech = 0                               
        if($challengeCollection[$x].Mechanisms.Count -ne 1)
        {
            $selectedMech = Read-Host "Choose mechanism"            
        }             
                 
        $mechResult = Centrify-Internal-AdvanceForMech -Mech $challengeCollection[$x].Mechanisms[$selectedMech] -Endpoint $endpoint -TenantId $tenantId -SessionId $authSessionId -WebSession $restResult.WebSession                           
    }
            
    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.WebSession.Cookies.GetCookies($endpoint)[".ASPXAUTH"].value
    
    Write-Output $finalResult        
}

function Centrify-Internal-AdvanceForMech {
    param(
        $mech,
        $endpoint,
        $tenantId,
        $sessionId,
        $websession
    )
    
    $advanceArgs = @{}
    $advanceArgs.TenantId = $tenantId
    $advanceArgs.SessionId = $sessionId
    $advanceArgs.MechanismId = $mech.MechanismId
    $advanceArgs.PersistentLogin = $false
    
    $prompt = Centrify-Internal-MechToPrompt -Mech $mech
    
    # Password, or other 'secret' string
    if($mech.AnswerType -eq "Text" -or $mech.AnswerType -eq "StartTextOob")    
    {    
        if($mech.AnswerType -eq "StartTextOob")
        {
            $advanceArgs.Action = "StartOOB"
            $advanceResult = (Centrify-InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult            
        }
            
        $responseSecure = Read-Host $prompt -assecurestring
        $responseBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($responseSecure)
        $responsePlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($responseBstr)
            
        $advanceArgs.Answer = $responsePlain
        $advanceArgs.Action = "Answer"
        $advanceArgsJson = $advanceArgs | ConvertTo-Json                      
                        
        $advanceResult = (Centrify-InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -JsonContent $advanceArgsJson -WebSession $websession -IncludeSessionInResult $true).RestResult
        if($advanceResult.success -ne $true -or 
            ($advanceResult.Result.Summary -ne "StartNextChallenge" -and $advanceResult.Result.Summary -ne "LoginSuccess" -and $advanceResult.Result.Summary -ne "NewPackage")
        )
        {            
            throw $advanceResult.Message
        }     
            
        return $advanceResult   
        break
    }
    # Out of band code or link which must be invoked remotely, we poll server
    elseif($mech.AnswerType -eq "StartOob")
    {
            # We ping advance once to get the OOB mech going, then poll for success or abject fail
            $advanceArgs.Action = "StartOOB"
            $advanceResult = (Centrify-InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult
            
            Write-Host $prompt
            $advanceArgs.Action = "Poll"
            do
            {
                Write-Host -NoNewline "."
                $advanceResult = (Centrify-InvokeREST -Endpoint $endpoint -Method "/security/advanceauthentication" -Token $null -ObjectContent $advanceArgs -WebSession $websession -IncludeSessionInResult $true).RestResult
                Start-Sleep -s 1                    
            } while($advanceResult.success -eq $true -and $advanceResult.Result.Summary -eq "OobPending")
            
            Write-Host ""   # new line
            
            # Polling done, did we succeed in our challenge?
            if($advanceResult.success -ne $true -or 
                ($advanceResult.Result.Summary -ne "StartNextChallenge" -and $advanceResult.Result.Summary -ne "LoginSuccess")
            )
            {            
                throw $advanceResult.Message
            } 
            return $advanceResult
            break
    }        
}

# Internal function, maps mechanism to description for selection
function Centrify-Internal-MechToDescription {
    param(
        $mech
    )
    
    if($mech.PromptSelectMech -ne $null)
    {
        return $mech.PromptSelectMech
    }
        
    $mechName = $mech.Name
    switch($mechName)
    {
        "UP" {
            return "Password"
        }                    
        "SMS" {
            return "SMS to number ending in " + $mech.PartialDeviceAddress
        }
        "EMAIL" {
            return "Email to address ending with " + $mech.PartialAddress
        }
        "PF" {
            return "Phone call to number ending with " + $mech.PartialPhoneNumber
        }
        "OATH" {
            return "OATH compatible client"
        }
        "SQ" {
            return "Security Question"
        }
        default {
            return $mechName
        }
    }
}

# Internal function, maps mechanism to prompt once selected
function Centrify-Internal-MechToPrompt {
    param(
        $mech        
    )
    
    if($mech.PromptMechChosen -ne $null)
    {
        return $mech.PromptMechChosen
    }
    
    $mechName = $mech.Name
    switch ($mechName)
    {
        "UP" {
            return "Password: "
        }
        "SMS" {
            return "Enter the code sent via SMS to number ending in " + $mech.PartialDeviceAddress
        }
        "EMAIL" {                    
            return "Click the link in the email " + $mech.PartialAddress + " or manually input the code"
        }
        "PF" {
            return "Calling number ending with " + $mech.PartialPhoneNumber + " please follow the spoken prompt"
        }
        "OATH" {
            return "Enter your current OATH code"
        }
        "SQ" {
            return "Enter the response to your secret question"
        }
        default {
            return $mechName
        }
    }
}

<# 
 .Synopsis
  Performs Authorization to an OAuth server in Application Services using Auth Code Flow.

 .Description
  Performs Authorization to an OAuth server in Application Services using Auth Code Flow. Returns 
  Access Bearer Token.

 .Parameter Endpoint
  The endpoint to authenticate against, required - must be tenant's url/pod

 .Example
   # Get an OAuth2 token for API calls to abc123.centrify.com
   Centrify-OAuthCodeFlow -Endpoint "https://abc123.centrify.com" -Appid "applicationId" -Clientid "client@domain" -Clientsecret "clientSec" -Scope "scope"
#>
function Centrify-OAuthCodeFlow()
{

    [CmdletBinding()]
        param(
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [string] $appid, 
        [Parameter(Mandatory=$true)]
        [string] $clientid,
        [Parameter(Mandatory=$true)]
        [string] $clientsecret,
        [Parameter(Mandatory=$true)]
        [string] $scope
    )

    $verbosePreference = "Continue"

	$config = @{}
	$config.authUri = "$endpoint/oauth2/authorize/$appid"
	$config.tokUri = "$endpoint/oauth2/token/$appid"
	$config.redirect = "$endpoint/sysinfo/dummy"	
	$config.clientID = $clientid
	$config.clientSecret =  $clientsecret
	$config.scope = $scope

	$restResult = centrify-InternalOAuthCodeFlow $config

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.access_token

    Write-Output $finalResult  

}

<# 
 .Synopsis
  Performs Authorization to an OAuth server in Application Services using Client Credentials Flow.

 .Description
  Performs Authorization to an OAuth server in Application Services using Client Credentials Flow. Returns 
  Access Bearer Token.

 .Parameter Endpoint
  The endpoint to authenticate against, required - must be tenant's url/pod

 .Example
   # Get an OAuth2 token for API calls to abc123.centrify.com
   Centrify-OAuthImplicit -Endpoint "https://abc123.centrify.com" -Appid "applicationId" -Clientid "client@domain" -Clientsecret "clientSec" -Scope "scope"
#>
function Centrify-OAuthImplicit()
{

   [CmdletBinding()]
   param(
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [string] $appid, 
        [Parameter(Mandatory=$true)]
        [string] $clientid,
        [Parameter(Mandatory=$true)]
        [string] $clientsecret,
        [Parameter(Mandatory=$true)]
        [string] $scope
    )

	$verbosePreference = "Continue"
	$config = @{}
	$config.authUri = "$hostURL/oauth2/authorize/$appid"
	$config.tokUri = "$hostURL/oauth2/token/$appid"
	$config.redirect = "$hostURL/sysinfo/dummy"
	$config.clientID = $clientid
	$config.clientSecret =  $clientsecret
	$config.scope = $scope

	$restResult = centrify-InternalImplicitFlow $config

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.access_token

    Write-Output $finalResult  
} 

<# 
 .Synopsis
  Performs Authorization to an OAuth server in Application Services using Client Credentials Flow.

 .Description
  Performs Authorization to an OAuth server in Application Services using Client Credentials Flow. Returns 
  Access Bearer Token.

 .Parameter Endpoint
  The endpoint to authenticate against, required - must be tenant's url/pod

 .Example
   # Get an OAuth2 token for API calls to abc123.centrify.com
   Centrify-OAuth-ClientCredentials -Endpoint "https://abc123.centrify.com" -Appid "applicationId" -Clientid "client@domain" -Clientsecret "clientSec" -Scope "scope"
#>
function Centrify-OAuth-ClientCredentials
{
    [CmdletBinding()]
    param(
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [string] $appid, 
        [Parameter(Mandatory=$true)]
        [string] $clientid,
        [Parameter(Mandatory=$true)]
        [string] $clientsecret,
        [Parameter(Mandatory=$true)]
        [string] $scope
    )

    $verbosePreference = "Continue"
    $api = "$endpoint/oauth2/token/$appid"
    $bod = @{}
    $bod.grant_type = "client_credentials"
    $bod.scope = $scope
    $basic = Centrify-InternalMakeClientAuth $clientid $clientsecret
    $restResult = Invoke-RestMethod -Method Post -Uri $api -Headers $basic -Body $bod

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.access_token

    Write-Output $finalResult  
}

<# 
 .Synopsis
  Performs Authorization to an OAuth server in Application Services using Resource Owner Flow.

 .Description
  Performs Authorization to an OAuth server in Application Services using Resource Owner Flow. Returns 
  Access Bearer Token.

 .Parameter Endpoint
  The endpoint to authenticate against, required - must be tenant's url/pod

 .Example
   # Get an OAuth2 token for API calls to abc123.centrify.com
   Centrify-OAuthResourceOwner -Endpoint "https://abc123.centrify.com" -Appid "applicationId" -Clientid "client@domain" -Clientsecret "clientSec" -Scope "scope"
#>
function Centrify-OAuthResourceOwner
{
    [CmdletBinding()]
    param(
        [string] $endpoint = "https://cloud.centrify.com",
        [Parameter(Mandatory=$true)]
        [string] $appid, 
        [Parameter(Mandatory=$true)]
        [string] $clientid,
        [string] $clientsecret,
        [string] $username,
        [Parameter(Mandatory=$true)]
        [string] $password,
        [Parameter(Mandatory=$true)]
        [string] $scope
    )

    $verbosePreference = "Continue"
    $api = "$endpoint/oauth2/token/$appid"
    $bod = @{}
    $bod.grant_type = "password"
    $bod.username = $username
    $bod.password = $password
    $bod.scope = $scope

    if($clientsecret)
    {
        $basic = Centrify-InternalMakeClientAuth $clientid $clientsecret
    }
    else
    {
        $basic = @{}
        $bod.client_id = $clientid
    }

    $restResult = Invoke-RestMethod -Method Post -Uri $api -Headers $basic -Body $bod

    $finalResult = @{}
    $finalResult.Endpoint = $endpoint    
    $finalResult.BearerToken = $restResult.access_token

    Write-Output $finalResult  
}

#Internal function for Auth Code Flow. Returns OAuth2 Access JWT Token
function Centrify-InternalOAuthCodeFlow($ocfg)

{

	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Web



	# build web UI
	$form = New-Object Windows.Forms.Form
	$form.Width = 640
	$form.Height = 480
	$web = New-Object Windows.Forms.WebBrowser
	$web.Size = $form.ClientSize
	$web.Anchor = "Left,Top,Right,Bottom"
	$form.Controls.Add($web)

	$Global:redirect_uri = $null

	# a handler for page change events in the browser
	$web.add_Navigated(
	{
		Write-Verbose "Navigated $($_.Url)"

		# detect when browser is about to fetch redirect_uri
		$uri = [uri] $ocfg.redirect

		if($_.Url.LocalPath -eq $uri.LocalPath) 
        {
			# collect authorization response in a global
			$Global:redirect_uri = $_.Url
			$form.DialogResult = "OK"
			$form.Close()
		}

	})

	write-verbose "host is $($ocfg.authUri)"
	write-verbose "client id is $($ocfg.clientID)"

	# navigate to authorize endpoint
	$web.Navigate("$($ocfg.authUri)?debug=true&scope=$($ocfg.scope)&response_type=code&redirect_uri=$($ocfg.redirect)&client_id=$($ocfg.clientID)&client_secret=$($ocfg.clientSecret)")

	# show browser window, waits for window to close
	if($form.ShowDialog() -ne "OK") 
    {
        Write-Verbose "WebBrowser: Canceled"
		return @{}
	}

	if(-not $Global:redirect_uri) 
    {
        Write-Verbose "WebBrowser: redirect_uri is null"
		return @{}
	}

	# decode query string of authorization code response
	$response = [Web.HttpUtility]::ParseQueryString($Global:redirect_uri.Query)

	if(-not $response.Get("code")) 
    {
		Write-Verbose "WebBrowser: authorization code is null"
		return @{}
	}

	$tokenrequest = @{ "grant_type" = "authorization_code"; "redirect_uri" = $ocfg.redirect; "code" = $response.Get("code") }

    Write-Verbose $tokenrequest.code


	if($ocfg.clientSecret)

	{
		# http basic authorization header for token request
		$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($ocfg.clientID):$($ocfg.clientSecret)"))
		$basic = @{ "Authorization" = "Basic $b64"}
	}
	else
	{
		$basic =@{}
		$tokenRequest.client_id = $ocfg.clientID
	}

	# send token request
	Write-Verbose "token-request: $([pscustomobject]$tokenrequest)"
    Write-Verbose $ocfg.tokUri

	try
	{
		$token = Invoke-RestMethod -Method Post -Uri $ocfg.tokUri -Headers $basic -Body $tokenrequest
	}
	catch [System.Net.WebException]
	{
		$e = $_.Exception
		Write-host "Exception caught: $e"
	}

	Write-Verbose "token-response: $($token)"

	return $token
}

#Internal function for Implicit Flow. Returns OAuth2 Access JWT Token
function Centrify-InternalImplicitFlow($ocfg)
{

	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Web

	# build web UI

	$form = New-Object Windows.Forms.Form
	$form.Width = 640
	$form.Height = 480
	$web = New-Object Windows.Forms.WebBrowser
	$web.Size = $form.ClientSize
	$web.Anchor = "Left,Top,Right,Bottom"
	$form.Controls.Add($web)   

	$Global:redirect_uri = $null

	# a handler for page change events in the browser
	$web.add_Navigated(
	{
		Write-Verbose "Navigated $($_.Url)"

		# detect when browser is about to fetch redirect_uri
		$uri = [uri] $ocfg.redirect

		if($_.Url.LocalPath -eq $uri.LocalPath) 
        {

			# collect authorization response in a global
			$Global:redirect_uri = $_.Url
			$form.DialogResult = "OK"
			$form.Close()
		}

	})

	write-verbose "host is $($ocfg.authUri)"
	write-verbose "client id is $($ocfg.clientID)"

	# navigate to authorize endpoint
	$web.Navigate("$($ocfg.authUri)?debug=true&scope=$($ocfg.scope)&response_type=code&redirect_uri=$($ocfg.redirect)&client_id=$($ocfg.clientID)&client_secret=$($ocfg.clientSecret)")

	# show browser window, waits for window to close
	if($form.ShowDialog() -ne "OK") 
    {
		Write-Verbose "WebBrowser: Canceled"
		return @{}
	}

	if(-not $Global:redirect_uri) 
    {
		Write-Verbose "WebBrowser: redirect_uri is null"
		return @{}
	}

	# decode query string of authorization code response
	$response = [Web.HttpUtility]::ParseQueryString($Global:redirect_uri.Query)

	if(-not $response.Get("code")) 
    {
		Write-Verbose "WebBrowser: authorization code is null"
		return @{}
	}

	$tokenrequest = @{ "grant_type" = "implicit"; "redirect_uri" = $ocfg.redirect; "code" = $response.Get("code") }

	if($ocfg.clientSecret)
	{

		# http basic authorization header for token request
		$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($ocfg.clientID):$($ocfg.clientSecret)"))
		$basic = @{ "Authorization" = "Basic $b64"}
	}

	else
	{

		$basic =@{}
		$tokenRequest.client_id = $ocfg.clientID
	}

	# send token request
	Write-Verbose "token-request: $([pscustomobject]$tokenrequest)"
	$token = Invoke-RestMethod -Method Post -Uri $ocfg.tokUri -Headers $basic -Body $tokenrequest
	Write-Verbose "token-response: $($token)"
	return $token

}

#Internal function. Returns base64 encoded auth token for basic Authorizatioin header.
function Centrify-InternalMakeClientAuth($id,$secret)
{
    # http basic authorization header for token request
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($id):$($secret)"))
    $basic = @{ "Authorization" = "Basic $b64"}
    return $basic
}

function Centrify-Get-IdForPrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,
        [string] $token,
        [string] $principalType,
        [string] $principal
    )
     Write-Verbose "Getting principal ID for principal " 
     # Get user role id
     # create a new

    if ($principalType -eq 'User') {  
        $query = "select InternalName  as ID from DsUsers where SystemName='$principal'"
    }
    elseif ($principalType -eq 'Role') { 
        $query = "select ID from Role where Name='$principal'"
    }
    else
    {
        Write-Output "Not a valid Ptype for $Principal, Type:  Type $principalType"
        return;
    }


    Write-Verbose "Getting Id for  $Principal, Type $principalType"

    $queryjs = @{ 'script' = $query}
         
    # make query and get id
    $idset = Centrify-InvokeREST -Endpoint $endpoint -Method "/RedRock/Query" -ObjectContent $queryjs -token $token -Verbose:$enableVerbose
    if($idset.success -eq $false)
    {
        Write-Output "Failed to get ID for $Principal, Type $principalType , Error : " $idset.Message
        return
    }
    if($idset.Result.Results.Length -eq 0)
    {
        Write-Output "Failed to get ID for $Principal, Type $principalType , Error :  Id not found" 
        return
    }
    Write-Verbose "Got Id for  $Prinicipal, Type $principalType $idset.Result.Results[0].Row "
    $id = @{}  
    $id.Id = $idset.Result.Results[0].Row  
    return $id
}


<# 
  .Synopsis
  Get Server ID. 

  .Description

  .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)  

  .Parameter ResourceName
  Name for the resource

  .Parameter Token
  Login token
  
  .Outpus
  ServerId - Server ID

  .Example
  Centrify-GetServerID -Endpoint 'https://pas.inforte.com.tr' -ResourceName 'MyWin2012' -Token $token

#>

function Centrify-GetServerID{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,       
        [Parameter(Mandatory=$true)]
        [string] $resourceName,        
        [Parameter(Mandatory=$true)]
        [string] $token    
    )
    try
    {              
        # get server ID
        Write-Verbose "Getting Server ID of $resourceName"
        $script = "select ID from Server where Name='$resourceName'"
        $query = @{ 'script' = $script }

        $serverGet = Centrify-InvokeREST -Endpoint $endpoint -Method "/Redrock/Query" -ObjectContent $query -Token $token -Verbose:$enableVerbose
        if ($serverGet.success -eq $false)
        {
            throw "Failed to get Server ID for $resourceName , Error: $serverGet.Message"
        }        
        if ($serverGet.Result.Results.Length -eq 0)
        {
            throw "Failed to get Server ID for $resourceName , Error: Server ID Not Found" 
        }
        Write-Verbose "Got ID for $resourceName, $serverGet"              
        $serverId = $serverGet.Result.Results[0].Row.ID        
        return $serverId
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Get Server ID Failed : $ErrorMessage $FailedItem"
        throw
    }
}


<# 
  .Synopsis
  Get Domain ID. 

  .Description

  .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)  

  .Parameter DomainName
  Name for the domain

  .Parameter Token
  Login token
  
  .Outpus
  DomainId - Domain ID 

  .Example
  Centrify-GetDomainID -Endpoint 'https://abc0123-dev.my-dev.centrify.com' -DomainName 'shirleyz.net' -Token $token
  
#>

function Centrify-GetDomainID{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,       
        [Parameter(Mandatory=$true)]
        [string] $domainName,
        [Parameter(Mandatory=$true)]
        [string] $token    
    )
    try
    {              
        # get domain ID
        Write-Verbose "Getting Domain ID of $domainName"
        $script = "select ID from VaultDomain where Name='$domainName'"
        $query = @{ 'script' = $script }

        $domainGet = Centrify-InvokeRest -Endpoint $endpoint -Method "/Redrock/Query" -ObjectContent $query -Token $token -Verbose:$enableVerbose
        if ($domainGet.success -eq $false)
        {
            throw "Failed to get Domain ID for $domainName , Error: $domainGet.Message"
        }        
        if ($domainGet.Result.Results.Length -eq 0)
        {
            throw "Failed to get Domain ID for $domainName , Error: Domain ID Not Found" 
        }
        Write-Verbose "Got ID for $domainName, $domainGet"              
        $domainId = $domainGet.Result.Results[0].Row.ID        
        return $domainId
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Get Domain ID Failed : $ErrorMessage $FailedItem"
        throw
    }
}


<# 
  .Synopsis
  Get Database ID. 

  .Description

  .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)  

  .Parameter DatabaseName
  Name for the database

  .Parameter Token
  Login token
  
  .Outpus
  DatabaseId - Database ID 

  .Example
  Centrify-GetDatabaseID -Endpoint 'https://abc0123-dev.my-dev.centrify.com' -DatabaseName 'db1' -Token $token
  
#>

function Centrify-GetDatabaseID{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,       
        [Parameter(Mandatory=$true)]
        [string] $databaseName,
        [Parameter(Mandatory=$true)]
        [string] $token    
    )
    try
    {              
        # get database ID
        Write-Verbose "Getting Database ID of $databaseName"
        $script = "select ID from VaultDatabase where Name='$databaseName'"
        $query = @{ 'script' = $script }

        $databaseGet = Centrify-InvokeRest -Endpoint $endpoint -Method "/Redrock/Query" -ObjectContent $query -Token $token -Verbose:$enableVerbose
        if ($databaseGet.success -eq $false)
        {
            throw "Failed to get Database ID for $databaseName , Error: $databaseGet.Message"
        }        
        if ($databaseGet.Result.Results.Length -eq 0)
        {
            throw "Failed to get Database ID for $databaseName , Error: Database ID Not Found" 
        }
        Write-Verbose "Got ID for $databaseName, $databaseGet"              
        $databaseId = $databaseGet.Result.Results[0].Row.ID        
        return $databaseId
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Get Database ID Failed : $ErrorMessage $FailedItem"
        throw
    }
}


<# 
  .Synopsis
  Get account ID. 

  .Description

  .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)  

  .Parameter AccountName
  Required - Name for the account 

  .Parameter ResourceName
  Name for the resource

  .Parameter DomainName
  Name for the domain

  .Parameter DatabaseName
  Name for the database

  .Parameter Token
  Login token
  
  .Outpus
  AccountId - Account ID 

  .Example
  Centrify-GetAccountID -Endpoint 'https://abc0123-dev.my-dev.centrify.com' -ResourceName 'MyWin2012' -AccountName 'admin2' -Token $token

  .Example
  Centrify-GetAccountID -Endpoint 'https://abc0123-dev.my-dev.centrify.com' -DomainName 'shirleyz.net' -AccountName 'testDomainAcct' -Token $token

  .Example
  Centrify-GetAccountID -Endpoint 'https://abc0123-dev.my-dev.centrify.com' -DatabaseName 'db1' -AccountName 'testDBAcct' -Token $token
  
#>


function Centrify-GetAccountID{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,            
        [string] $resourceName,
        [string] $domainName,
        [string] $databaseName,
        [Parameter(Mandatory=$true)]     
        [string] $accountName,
        [Parameter(Mandatory=$true)]
        [string] $token    
    )
    try
    {   
        if ($resourceName)
        {
            $serverId = Centrify-GetServerID -Endpoint $endpoint -ResourceName $resourceName -Token $token -Verbose:$enableVerbose
            $scriptVa = "select ID from VaultAccount where User='$accountName' and Host='$serverId'"
        }
        elseif ($domainName)
        {
            $domainId = Centrify-GetDomainID -Endpoint $endpoint -DomainName $domainName -Token $token -Verbose:$enableVerbose
            $scriptVa = "select ID from VaultAccount where User='$accountName' and DomainID='$domainId'"
        } 
        elseif ($databaseName)
        {
            $databaseId = Centrify-GetDatabaseID -Endpoint $endpoint -DatabaseName $databaseName -Token $token -Verbose:$enableVerbose
            $scriptVa = "select ID from VaultAccount where User='$accountName' and DatabaseID='$databaseId'"
        }
        else
        {
            throw "Failed to get account ID for $accountName , Error: Missing parameter: resource/domain/database name"
        }         
        
        # get account ID
        Write-Verbose "Getting account ID of $accountName"        
        $queryVa = @{ 'script' = $scriptVa }
               
        $accountGet = Centrify-InvokeRest -Endpoint $endpoint -Method "/Redrock/Query" -ObjectContent $queryVa -Token $token -Verbose:$enableVerbose
        if ($accountGet.success -eq $false)
        {
            throw "Failed to get account ID for $accountName , Error: $accountGet.Message"
        }
        if ($accountGet.Result.Results.Length -eq 0)
        {
            throw "Failed to get account ID for $accountName , Error: Account ID Not Found"
        }
        Write-Verbose "Got ID for $accountName, $accountGet"            
        $accountId = $accountGet.Result.Results[0].Row.ID
        return $accountId
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error "Get account ID Failed : $ErrorMessage $FailedItem"
        throw
    }
}

function Centrify-GetUserFromPrincipalID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,            
        [string] $token,
        $UserID    
    )

    $queryvault = "select user from VaultAccount where ID=$UserID'"
    $queryvaultyjs = @{ 'script' = $queryvault}
    $queryvaultResult = Centrify-InvokeREST -Method "/redrock/query"  -Endpoint $token.Endpoint -Token $BearerToken -ObjectContent $queryvaultyjs  -Verbose:$enableVerbose

    return $user

    }
Export-ModuleMember -function Centrify-InvokeREST
Export-ModuleMember -function Centrify-InteractiveLogin-GetToken
Export-ModuleMember -function Centrify-CertSsoLogin-GetToken
Export-ModuleMember -function Centrify-OAuthCodeFlow
Export-ModuleMember -function Centrify-OAuthImplicit
Export-ModuleMember -function Centrify-OAuth-ClientCredentials
Export-ModuleMember -function Centrify-OAuthResourceOwner
Export-ModuleMember -function Centrify-Get-IdForPrincipal
Export-ModuleMember -function Centrify-GetServerID
Export-ModuleMember -function Centrify-GetDomainID
Export-ModuleMember -function Centrify-GetDatabaseID
Export-ModuleMember -function Centrify-GetAccountID
Export-ModuleMember -function Centrify-GetUserFromPrincipalID